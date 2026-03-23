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

/* Build .rsrc section for PE icon embedding.
 *
 * PE resource tree for icon:
 *   Root DIR → [RT_ICON(3)]    → [ID 1..N] → [lang 0x0409] → DATA_ENTRY → raw icon
 *            → [RT_GROUP_ICON(14)] → [ID 1] → [lang 0x0409] → DATA_ENTRY → GRPICONDIR
 *
 * Each node is a 16-byte DIR header + 8-byte entries.
 * Leaf entries point to 16-byte DATA_ENTRY structs.
 * DATA_ENTRY has RVA to actual data.
 */
static int build_rsrc(uint8_t *out, uint32_t rva, const uint8_t *ico, long isz) {
    if (!ico || isz < 22) return 0;
    uint16_t n = *(uint16_t*)(ico + 4); /* number of icon images */
    if (!n || n > 10) return 0;

    memset(out, 0, 65536);
    int W = 0; /* write cursor */

    /* === Phase 1: directories + entries (tree structure) === */

    /* Root directory: 2 type entries (RT_ICON=3, RT_GROUP_ICON=14) */
    int root = W;
    *(uint16_t*)(out+W+12) = 0;                  /* NumberOfNamedEntries = 0 */
    *(uint16_t*)(out+W+14) = 2;                  /* NumberOfIdEntries = 2 */
    W += 16;
    int root_e0 = W; W += 8;                     /* entry for RT_ICON */
    int root_e1 = W; W += 8;                     /* entry for RT_GROUP_ICON */

    /* RT_ICON subdir: N entries (one per icon image) */
    int icon_dir = W;
    *(uint32_t*)(out+root_e0) = 3;               /* ID = RT_ICON */
    *(uint32_t*)(out+root_e0+4) = W | 0x80000000;/* offset to subdir */
    *(uint16_t*)(out+W+14) = n; W += 16;          /* DIR: N ID entries */
    int icon_id_entries = W; W += n * 8;

    /* Per-icon language subdirs */
    int icon_lang_entry[10]; /* offset of each language ENTRY (where we'll set data_entry offset) */
    for (int i = 0; i < n; i++) {
        int lang_dir = W;
        *(uint32_t*)(out+icon_id_entries+i*8) = i + 1;        /* ID = i+1 */
        *(uint32_t*)(out+icon_id_entries+i*8+4) = W | 0x80000000; /* → lang subdir */
        *(uint16_t*)(out+W+14) = 1; W += 16;                   /* DIR: 1 ID entry */
        icon_lang_entry[i] = W;
        *(uint32_t*)(out+W) = 0x0409;                         /* lang = en-US */
        /* out+W+4 = offset to DATA_ENTRY — filled in phase 2 */
        W += 8;
    }

    /* RT_GROUP_ICON subdir: 1 entry */
    int group_dir = W;
    *(uint32_t*)(out+root_e1) = 14;              /* ID = RT_GROUP_ICON */
    *(uint32_t*)(out+root_e1+4) = W | 0x80000000;
    *(uint16_t*)(out+W+14) = 1; W += 16;          /* DIR: 1 ID entry */
    int group_id_entry = W;
    *(uint32_t*)(out+W) = 1; W += 8;             /* ID = 1 */

    /* Group language subdir */
    int group_lang_dir = W;
    *(uint32_t*)(out+group_id_entry+4) = W | 0x80000000;
    *(uint16_t*)(out+W+12) = 1; W += 16;
    int group_lang_entry = W;
    *(uint32_t*)(out+W) = 0x0409; W += 8;

    /* === Phase 2: DATA_ENTRY structs === */

    /* Icon data entries (one per image) */
    int icon_de[10];
    for (int i = 0; i < n; i++) {
        icon_de[i] = W;
        *(uint32_t*)(out+icon_lang_entry[i]+4) = W; /* lang entry → data entry (NO high bit) */
        /* DATA_ENTRY: data_rva(4), size(4), codepage(4), reserved(4) */
        uint32_t img_sz = *(uint32_t*)(ico + 6 + i*16 + 8);
        *(uint32_t*)(out+W+4) = img_sz;    /* size */
        /* data_rva filled in phase 3 */
        W += 16;
    }

    /* Group icon data entry */
    int group_de = W;
    *(uint32_t*)(out+group_lang_entry+4) = W;
    /* size filled in phase 3 */
    W += 16;

    /* === Phase 3: raw data === */
    W = ALIGN(W, 4);

    /* Icon image data */
    for (int i = 0; i < n; i++) {
        uint32_t img_sz = *(uint32_t*)(ico + 6 + i*16 + 8);
        uint32_t img_off = *(uint32_t*)(ico + 6 + i*16 + 12);
        *(uint32_t*)(out+icon_de[i]) = rva + W;  /* fix DATA_ENTRY.data_rva */
        memcpy(out + W, ico + img_off, img_sz);
        W += ALIGN(img_sz, 4);
    }

    /* GRPICONDIR data */
    int grp_start = W;
    *(uint32_t*)(out+group_de) = rva + W;        /* fix DATA_ENTRY.data_rva */
    *(uint16_t*)(out+W) = 0;                     /* reserved */
    *(uint16_t*)(out+W+2) = 1;                   /* type = icon */
    *(uint16_t*)(out+W+4) = n;                   /* count */
    W += 6;
    for (int i = 0; i < n; i++) {
        uint8_t *ide = (uint8_t*)(ico + 6 + i*16);
        out[W] = ide[0];                         /* width */
        out[W+1] = ide[1];                       /* height */
        out[W+2] = ide[2];                       /* color count */
        out[W+3] = 0;                            /* reserved */
        *(uint16_t*)(out+W+4) = *(uint16_t*)(ide+4); /* planes */
        *(uint16_t*)(out+W+6) = *(uint16_t*)(ide+6); /* bit count */
        *(uint32_t*)(out+W+8) = *(uint32_t*)(ide+8); /* bytes in resource */
        *(uint16_t*)(out+W+12) = i + 1;          /* ID */
        W += 14;
    }
    *(uint32_t*)(out+group_de+4) = W - grp_start; /* fix size */

    return ALIGN(W, FA);
}

/* Load pre-linked .rsrc section and rebase RVAs */
static int load_rsrc_bin(uint8_t *out, uint32_t new_rva, const char *path, uint32_t old_rva) {
    long sz = 0;
    uint8_t *data = readf(path, &sz);
    if (!data || sz < 16) return 0;
    memcpy(out, data, sz);
    free(data);
    /* Rebase: fix DATA_ENTRY RVA fields (values in range [old_rva, old_rva+sz)) */
    int32_t delta = (int32_t)new_rva - (int32_t)old_rva;
    if (delta != 0) {
        for (long i = 0; i + 4 <= sz; i += 4) {
            uint32_t v = *(uint32_t*)(out + i);
            if (v >= old_rva && v < old_rva + (uint32_t)sz)
                *(uint32_t*)(out + i) = v + delta;
        }
    }
    printf("  .rsrc: %ld bytes, rebased 0x%x->0x%x\n", sz, old_rva, new_rva);
    return ALIGN(sz, FA);
}

int main(int argc, char **argv) {
    const char *elf_path=0,*ico_path=0,*out_path=0,*rsrc_path=0;
    uint32_t rsrc_old_rva=0;
    for(int i=1;i<argc;i++){
        if(!strcmp(argv[i],"-icon")&&i+1<argc) ico_path=argv[++i];
        else if(!strcmp(argv[i],"-rsrc")&&i+1<argc) rsrc_path=argv[++i];
        else if(!strcmp(argv[i],"-rsrc-rva")&&i+1<argc) rsrc_old_rva=strtoul(argv[++i],0,0);
        else if(!strcmp(argv[i],"-o")&&i+1<argc) out_path=argv[++i];
        else if(!elf_path) elf_path=argv[i];
    }
    if(!elf_path||!out_path){fprintf(stderr,"Usage: mkape <elf> [-icon ico | -rsrc bin -rsrc-rva 0xNNNN] -o out.exe\n");return 1;}

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
    if(rsrc_path) rsrc_sz=load_rsrc_bin(rsrc,(uint32_t)rsrc_rva,rsrc_path,rsrc_old_rva);
    else if(ico) rsrc_sz=build_rsrc(rsrc,(uint32_t)rsrc_rva,ico,isz);
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
