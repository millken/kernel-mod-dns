#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h> 
#include <linux/netfilter.h> 
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

/* These are Required for NETFILTER functionality */
#include <net/checksum.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/interrupt.h>

#define PROCFS_NAME "dnsc"
#define QUAN 16
#define UDP 17

#define INDNS "10.0.0.1"

/* google */
#define OUTDNS_01 "8.8.8.8"
#define OUTDNS_02 "8.8.4.4"

/* opendns */
#define OUTDNS_03 "208.67.222.222"
#define OUTDNS_04 "208.67.220.220"

MODULE_AUTHOR("Matus Bursa");
MODULE_DESCRIPTION("dnsnat");
MODULE_LICENSE("Beerware");

static struct nf_hook_ops nfho;   //net filter hook option struct
static struct nf_hook_ops nfho_post;
static struct proc_dir_entry *dnsc;
static int port_count;
static int port[QUAN];
static int count;
struct sk_buff *sock_buff;
struct iphdr *ip_header;            //ip header struct
struct udphdr *udp_header; 

unsigned int 
inet_addr(char *str) 
{ 
  int a,b,c,d; 
  char arr[4]; 
  sscanf(str,"%d.%d.%d.%d",&a,&b,&c,&d); 
  arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d; 
  return *(unsigned int*)arr; 
} 

static int 
dnsc_read (struct seq_file *m, void *v)
{
  seq_printf(m, "%d\n", count);
  return 0;
}

static int proc_open(struct inode *inode, struct  file *file) {
  return single_open(file, dnsc_read, NULL);
}

static const struct file_operations proc_file_fops = {
 .owner = THIS_MODULE,
 .open  = proc_open,
 .read  = seq_read,
 .llseek = seq_lseek,
 .release = single_release,
};


unsigned int 
hook_func(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in, 
            const struct net_device *out, int (*okfn)(struct sk_buff *))
{
        int i;
        sock_buff = skb;
        ip_header = (struct iphdr *)skb_network_header(sock_buff);    //grab network header using accessor
        udp_header = (struct udphdr *)((__u32 *)ip_header+ ip_header->ihl);
        
        if(!sock_buff) { return NF_ACCEPT; }
 
        if (ip_header->protocol==UDP && ntohs(udp_header->source) == 53) {
            for (i = 0; i < QUAN; i++) {
              if (port[i] == ntohs(udp_header->dest)) {
                count++;
                ip_header->check = 0;
                ip_header->saddr = inet_addr(INDNS);
                ip_header->check = ip_fast_csum((u8 *) ip_header, ip_header->ihl);
        } } } 
    
        return NF_ACCEPT;
}

unsigned int 
post_hook(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in, 
            const struct net_device *out, int (*okfn)(struct sk_buff *))
{
        char dest[16];
        int datalen;
        static int balance = 0;
        
        sock_buff = skb;
        ip_header = (struct iphdr *)skb_network_header(sock_buff);    //grab network header using accessor
        udp_header = (struct udphdr *)((__u32 *)ip_header + ip_header->ihl);

        if(!sock_buff) { return NF_ACCEPT;}

        if (ip_header->protocol==UDP && ntohs(udp_header->dest) == 53) {
            snprintf(dest, 16, "%pI4", &ip_header->daddr);
            if (strcmp(dest, INDNS) == 0) {
              datalen = sock_buff->len - ip_header->ihl * 4;
              ip_header->check = 0;
              if (balance == 0) {
                balance = 1;
                ip_header->daddr = inet_addr(OUTDNS_01);
              } else if (balance == 1) {
                balance = 2;
                ip_header->daddr = inet_addr(OUTDNS_02);
              } else if (balance == 2) {
                balance = 3;
                ip_header->daddr = inet_addr(OUTDNS_03);
              } else if (balance == 3) {
                balance = 0;
                ip_header->daddr = inet_addr(OUTDNS_04);
              }

              ip_header->check = ip_fast_csum((u8 *) ip_header, ip_header->ihl);
              udp_header->check = ~csum_tcpudp_magic(ip_header->saddr, ip_header->daddr, datalen, IPPROTO_UDP, 0);

              port[port_count] = ntohs(udp_header->source);
              port_count++;
              if (port_count == QUAN)
                port_count = 0;
        } }

        return NF_ACCEPT;
}

int 
init_module()
{
	      count = 0;
        port_count = 0;
        nfho.hook = hook_func;
        nfho.hooknum = NF_INET_PRE_ROUTING;
        nfho.pf = PF_INET;
        nfho.priority = NF_IP_PRI_LAST;

        nfho_post.hook = post_hook;
        nfho_post.hooknum = NF_INET_POST_ROUTING;
        nfho_post.pf = PF_INET;
        nfho_post.priority = NF_IP_PRI_LAST;
 
        nf_register_hook(&nfho);
        nf_register_hook(&nfho_post);
        
	      dnsc = proc_create(PROCFS_NAME, 0, NULL, &proc_file_fops);
        if (dnsc == NULL) {
          remove_proc_entry(PROCFS_NAME, NULL);
          printk(KERN_ALERT "Error: Could not initialize /proc/%s\n", PROCFS_NAME);
          return -ENOMEM;
        } 

        return 0;
}
 
void 
cleanup_module()
{
        nf_unregister_hook(&nfho);     
        nf_unregister_hook(&nfho_post);
        remove_proc_entry(PROCFS_NAME, NULL);
}
