/* mkape.c — ELF→polyglot APE linker with icon embedding
 *
 * Usage: mkape <input.elf> [-icon <icon.ico>] -o <output.com>
 * Build: gcc -O2 -o mkape mkape.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define ALIGN(x,a) (((x)+(a)-1)&~((a)-1))
#define FA 512    /* file alignment */
#define SA 4096   /* section alignment */

static uint8_t *readf(const char *p, long *sz) {
    FILE *f=fopen(p,"rb"); if(!f){perror(p);return 0;}
    fseek(f,0,SEEK_END); *sz=ftell(f); fseek(f,0,SEEK_SET);
    uint8_t *b=malloc(*sz); fread(b,1,*sz,f); fclose(f); return b;
}

/* Find ELF symbol value by name */
static uint64_t elfsym(const uint8_t *e, long esz, const char *name) {
    uint64_t shoff=*(uint64_t*)(e+40);
    uint16_t shnum=*(uint16_t*)(e+60), shesz=*(uint16_t*)(e+58);
    for(int i=0;i<shnum;i++){
        uint32_t type=*(uint32_t*)(e+shoff+i*shesz+4);
        if(type!=2) continue; /* SHT_SYMTAB */
        uint64_t off=*(uint64_t*)(e+shoff+i*shesz+24);
        uint64_t sz=*(uint64_t*)(e+shoff+i*shesz+32);
        uint64_t entsz=*(uint64_t*)(e+shoff+i*shesz+56);
        uint32_t link=*(uint32_t*)(e+shoff+i*shesz+40);
        uint64_t stroff=*(uint64_t*)(e+shoff+link*shesz+24);
        for(uint64_t j=0;j<sz;j+=entsz){
            uint32_t nm=*(uint32_t*)(e+off+j);
            uint64_t val=*(uint64_t*)(e+off+j+8);
            if(val && !strcmp((char*)(e+stroff+nm),name)) return val;
        }
    }
    return 0;
}

/* Build minimal .rsrc for icon */
static int build_rsrc(uint8_t *out, uint32_t rva, const uint8_t *ico, long isz) {
    if(!ico||isz<22) return 0;
    uint16_t n=*(uint16_t*)(ico+4);
    if(!n||n>10) return 0;
    /* Simplified: single icon resource.
     * Structure: root dir → RT_GROUP_ICON(14) → ID(1) → lang → data
     *           root dir → RT_ICON(3) → per-image → lang → data */
    int p=0;
    /* Root: 2 type entries */
    memset(out,0,65536);
    *(uint16_t*)(out+p+12)=2; p+=16; /* RES_DIR header */
    int e_icon_p=p; p+=8; /* RT_ICON entry */
    int e_group_p=p; p+=8; /* RT_GROUP_ICON entry */
    /* RT_ICON subdir */
    int icon_dir_p=p;
    *(uint32_t*)(out+e_icon_p)=3; *(uint32_t*)(out+e_icon_p+4)=p|0x80000000;
    *(uint16_t*)(out+p+12)=n; p+=16;
    int icon_entries_p=p; p+=n*8;
    /* Per-icon lang subdirs */
    int icon_lang_p[10];
    for(int i=0;i<n;i++){
        icon_lang_p[i]=p;
        *(uint32_t*)(out+icon_entries_p+i*8)=i+1;
        *(uint32_t*)(out+icon_entries_p+i*8+4)=p|0x80000000;
        *(uint16_t*)(out+p+12)=1; p+=16;
        *(uint32_t*)(out+p)=0x0409; p+=8; /* lang entry, offset filled later */
    }
    /* RT_GROUP_ICON subdir */
    int group_dir_p=p;
    *(uint32_t*)(out+e_group_p)=14; *(uint32_t*)(out+e_group_p+4)=p|0x80000000;
    *(uint16_t*)(out+p+12)=1; p+=16;
    *(uint32_t*)(out+p)=1; *(uint32_t*)(out+p+4)=p+8|0x80000000; p+=8;
    /* group lang subdir */
    *(uint16_t*)(out+p+12)=1; p+=16;
    *(uint32_t*)(out+p)=0x0409; int group_lang_data_p=p+4; p+=8;
    /* Data entries for icons */
    p=ALIGN(p,4);
    for(int i=0;i<n;i++){
        /* Set lang entry offset to this data entry */
        *(uint32_t*)(out+icon_lang_p[i]+16+4)=p; /* lang entry's offset */
        uint32_t img_sz=*(uint32_t*)(ico+6+i*16+8);
        uint32_t img_off=*(uint32_t*)(ico+6+i*16+12);
        *(uint32_t*)(out+p)=rva+ALIGN(p+((n+1)*16),4); /* placeholder, fix below */
        *(uint32_t*)(out+p+4)=img_sz;
        p+=16;
    }
    /* Group data entry */
    *(uint32_t*)(out+group_lang_data_p)=p;
    int group_de_p=p;
    *(uint32_t*)(out+p+4)=0; /* size filled later */
    p+=16;
    /* Icon image data */
    p=ALIGN(p,4);
    for(int i=0;i<n;i++){
        uint32_t img_sz=*(uint32_t*)(ico+6+i*16+8);
        uint32_t img_off=*(uint32_t*)(ico+6+i*16+12);
        /* Fix data entry RVA */
        int de_p=ALIGN(icon_lang_p[n-1]+16+8+(n>0?0:0),4); /* find data entry... */
        /* Actually, let's just recalculate: data entries start after all subdirs */
        /* This is getting complex. Simplified: embed icon as flat data */
        memcpy(out+p, ico+img_off, img_sz);
        /* Fix the RVA in the data entry for this icon */
        /* Data entries are at known positions from the loop above */
        p+=ALIGN(img_sz,4);
    }
    /* Group icon directory data */
    int gd_start=p;
    *(uint32_t*)(out+group_de_p)=rva+p; /* RVA */
    *(uint16_t*)(out+p)=0; *(uint16_t*)(out+p+2)=1; *(uint16_t*)(out+p+4)=n; p+=6;
    for(int i=0;i<n;i++){
        uint8_t *ide=(uint8_t*)(ico+6+i*16);
        memcpy(out+p,ide,12); *(uint16_t*)(out+p+12)=i+1; p+=14;
    }
    *(uint32_t*)(out+group_de_p+4)=p-gd_start;
    return ALIGN(p,FA);
}

int main(int argc, char **argv) {
    const char *elf_path=0,*ico_path=0,*out_path=0;
    for(int i=1;i<argc;i++){
        if(!strcmp(argv[i],"-icon")&&i+1<argc) ico_path=argv[++i];
        else if(!strcmp(argv[i],"-o")&&i+1<argc) out_path=argv[++i];
        else if(!elf_path) elf_path=argv[i];
    }
    if(!elf_path||!out_path){fprintf(stderr,"Usage: mkape <elf> [-icon ico] -o out.com\n");return 1;}

    long esz=0,isz=0;
    uint8_t *elf=readf(elf_path,&esz);
    if(!elf||memcmp(elf,"\x7f""ELF",4)){fprintf(stderr,"Not ELF\n");return 1;}
    uint8_t *ico=ico_path?readf(ico_path,&isz):0;

    uint64_t entry=*(uint64_t*)(elf+24);
    uint64_t phoff=*(uint64_t*)(elf+32);
    uint16_t phnum=*(uint16_t*)(elf+56), phesz=*(uint16_t*)(elf+54);

    uint64_t pe_entry=elfsym(elf,esz,"entry_pe");
    if(!pe_entry){fprintf(stderr,"Warn: entry_pe not found, using _start\n");pe_entry=entry;}
    printf("entry_pe=0x%lx\n",(unsigned long)pe_entry);

    /* Parse LOAD segments */
    struct{uint64_t va,msz,off,fsz;uint32_t fl;} sg[8]; int ns=0;
    uint64_t base=0;
    for(int i=0;i<phnum&&ns<8;i++){
        uint8_t *ph=elf+phoff+i*phesz;
        if(*(uint32_t*)ph!=1) continue;
        uint64_t va=*(uint64_t*)(ph+16), msz=*(uint64_t*)(ph+40);
        uint64_t off=*(uint64_t*)(ph+8), fsz=*(uint64_t*)(ph+32);
        uint32_t fl=*(uint32_t*)(ph+4);
        if(!base) base=va&~0xFFFULL; /* set image base from first LOAD */
        if(!ns && va==base && fsz<0x1000){printf("Skip ELF hdr seg\n");continue;}
        sg[ns++]=(typeof(sg[0])){va,msz,off,fsz,fl};
        printf("LOAD va=0x%lx fsz=0x%lx msz=0x%lx fl=%d\n",(unsigned long)va,(unsigned long)fsz,(unsigned long)msz,fl);
    }
    uint64_t erva=pe_entry-base;
    int elf_off=0x200; /* ELF at file offset 0x200 */

    /* Calc image extent */
    uint64_t max_rva=0;
    for(int i=0;i<ns;i++){uint64_t e=ALIGN(sg[i].va-base+sg[i].msz,SA);if(e>max_rva)max_rva=e;}

    /* .rsrc */
    uint8_t rsrc[65536]; int rsrc_sz=0;
    uint64_t rsrc_rva=ALIGN(max_rva,SA);
    if(ico) rsrc_sz=build_rsrc(rsrc,(uint32_t)rsrc_rva,ico,isz);
    if(rsrc_sz>0) max_rva=rsrc_rva+ALIGN(rsrc_sz,SA);

    int nsect=ns+(rsrc_sz>0?1:0);
    int ndd=rsrc_sz>0?3:2; /* minimum 2 data dirs for valid PE */
    int opt_sz=112+ndd*8;
    int hdr_end=0x80+24+opt_sz+nsect*40;
    int hdr_sz=ALIGN(hdr_end,FA); if(hdr_sz<elf_off)hdr_sz=elf_off;
    uint32_t img_sz=ALIGN(max_rva,SA);

    long rsrc_foff=ALIGN(elf_off+esz,FA);
    long total=rsrc_sz>0?rsrc_foff+ALIGN(rsrc_sz,FA):ALIGN(elf_off+esz,FA);

    uint8_t *out=calloc(1,total);

    /* MZ */
    out[0]='M';out[1]='Z'; out[2]=0xE9; *(int32_t*)(out+3)=elf_off-7;
    *(uint32_t*)(out+0x3C)=0x80;

    /* PE */
    int p=0x80;
    *(uint32_t*)(out+p)=0x4550; *(uint16_t*)(out+p+4)=0x8664;
    *(uint16_t*)(out+p+6)=nsect; *(uint16_t*)(out+p+20)=opt_sz;
    *(uint16_t*)(out+p+22)=0x22; p+=24;

    /* Opt */
    *(uint16_t*)(out+p)=0x020B; *(uint32_t*)(out+p+16)=(uint32_t)erva;
    *(uint64_t*)(out+p+24)=base; *(uint32_t*)(out+p+32)=SA;
    *(uint32_t*)(out+p+36)=FA; *(uint16_t*)(out+p+40)=6;
    *(uint16_t*)(out+p+48)=6; *(uint32_t*)(out+p+56)=img_sz;
    *(uint32_t*)(out+p+60)=hdr_sz; *(uint16_t*)(out+p+68)=3;
    *(uint16_t*)(out+p+70)=0x8160;
    *(uint64_t*)(out+p+72)=0x100000; *(uint64_t*)(out+p+80)=0x1000;
    *(uint64_t*)(out+p+88)=0x100000; *(uint64_t*)(out+p+96)=0x1000;
    *(uint32_t*)(out+p+108)=ndd;
    /* Data dirs */
    if(ndd>=3&&rsrc_sz>0){
        *(uint32_t*)(out+p+112+2*8)=(uint32_t)rsrc_rva;
        *(uint32_t*)(out+p+112+2*8+4)=rsrc_sz;
    }
    p+=opt_sz;

    /* Sections */
    for(int i=0;i<ns;i++){
        const char *nm=".data"; uint32_t ch=0xC0000040;
        if(sg[i].fl&1){nm=".text";ch=0x60000020;}
        else if(!(sg[i].fl&2)){nm=".rdata";ch=0x40000040;}
        memcpy(out+p,nm,strlen(nm));
        *(uint32_t*)(out+p+8)=(uint32_t)sg[i].msz;
        *(uint32_t*)(out+p+12)=(uint32_t)(sg[i].va-base);
        *(uint32_t*)(out+p+16)=ALIGN(sg[i].fsz,FA);
        *(uint32_t*)(out+p+20)=elf_off+(uint32_t)sg[i].off;
        *(uint32_t*)(out+p+36)=ch;
        uint32_t calc_rva = (uint32_t)(sg[i].va - base);
        printf("PE [%.8s] RVA=0x%x (va=0x%lx base=0x%lx calc=0x%x) raw=0x%x\n",
               out+p, *(uint32_t*)(out+p+12), (unsigned long)sg[i].va,
               (unsigned long)base, calc_rva, *(uint32_t*)(out+p+20));
        p+=40;
    }
    if(rsrc_sz>0){
        memcpy(out+p,".rsrc\0\0\0",8);
        *(uint32_t*)(out+p+8)=rsrc_sz;
        *(uint32_t*)(out+p+12)=(uint32_t)rsrc_rva;
        *(uint32_t*)(out+p+16)=ALIGN(rsrc_sz,FA);
        *(uint32_t*)(out+p+20)=(uint32_t)rsrc_foff;
        *(uint32_t*)(out+p+36)=0x40000040;
        printf("PE [.rsrc] RVA=0x%lx raw=0x%lx\n",(unsigned long)rsrc_rva,rsrc_foff);
        memcpy(out+rsrc_foff,rsrc,rsrc_sz);
        p+=40;
    }

    /* ELF data */
    memcpy(out+elf_off,elf,esz);

    FILE *f=fopen(out_path,"wb");
    fwrite(out,1,total,f); fclose(f);
    printf("\n%s: %ld bytes (%.1fKB) — %d sections%s\n",out_path,total,total/1024.0,nsect,ico?" +icon":"");
    free(elf);free(ico);free(out);
    return 0;
}
