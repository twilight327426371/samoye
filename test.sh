#!/bin/bash

#/opt/sandstone/bin/sds pg dump | awk '
# /^pg_stat/ { col=1; while($col!="up") {col++}; col++ }
# /^[0-9a-f]+\.[0-9a-f]+/ { match($0,/^[0-9a-f]+/); pool=substr($0, RSTART, RLENGTH); poollist[pool]=0;
# up=$col; i=0; RSTART=0; RLENGTH=0; delete osds; while(match(up,/[0-9]+/)>0) { osds[++i]=substr(up,RSTART,RLENGTH); up = substr(up, RSTART+RLENGTH) }
# for(i in osds) {array[osds[i],pool]++; osdlist[osds[i]];}
#}
#END {
# printf("\n");
# printf("pool :\t"); for (i in poollist) printf("%s\t",i); printf("| SUM \n");
# for (i in poollist) printf("--------"); printf("----------------\n");
# for (i in osdlist) { printf("osd.%i\t", i); sum=0;
# for (j in poollist) { printf("%i\t", array[i,j]); sum+=array[i,j]; poollist[j]+=array[i,j] }; printf("| %i\n",sum) }
# for (i in poollist) printf("--------"); printf("----------------\n");
# printf("SUM :\t"); for (i in poollist) printf("%s\t",poollist[i]); printf("|\n");
#}'

/opt/sandstone/bin/sds pg dump | awk '
 /^pg_stat/ { col=1; while($col!="up") {col++}; col++ }
 /^[0-9a-f]+\.[0-9a-f]+/ { match($0,/^[0-9a-f]+/); pool=substr($0, RSTART, RLENGTH); poollist[pool]=0;
 up=$col; i=0; RSTART=0; RLENGTH=0; delete osds; while(match(up,/[0-9]+/)>0) { osds[++i]=substr(up,RSTART,RLENGTH); up = substr(up, RSTART+RLENGTH) }
 for(i in osds) {array[osds[i],pool]++; osdlist[osds[i]];}
}
END {
 printf("\n");
 slen=asorti(poollist,newpoollist);
 printf("pool :\t");for (i=1;i<=slen;i++) {printf("%s\t", newpoollist[i])}; printf("| SUM \n");
 for (i in poollist) printf("--------"); printf("----------------\n");
 slen1=asorti(osdlist,newosdlist)
 delete poollist;
 for (i=1;i<=slen1;i++) { printf("osd.%i\t", newosdlist[i]); sum=0; 
 for (j=1;j<=slen;j++)  { printf("%i\t", array[newosdlist[i],newpoollist[j]]); sum+=array[newosdlist[i],newpoollist[j]]; poollist[j]+=array[newosdlist[i],newpoollist[j]] }; printf("| %i\n",sum)
} 
for (i in poollist) printf("--------"); printf("----------------\n");
 printf("SUM :\t"); for (i=1;i<=slen;i++) printf("%s\t",poollist[i]); printf("|\n");
}'
