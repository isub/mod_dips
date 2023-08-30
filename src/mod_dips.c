
#define MOD_NAME "mod_dips: "

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

MODULE_AUTHOR( "isub <sa-bir@yandex.ru>" );
MODULE_DESCRIPTION( "drop ipsec ip-packets test module" );
MODULE_LICENSE( "GPL" );

static struct nf_hook_ops gs_sHookOps;
static unsigned int gs_uiItGotIPSEC;

static unsigned int hook_fn( void * priv, struct sk_buff * skb, const struct nf_hook_state * state );

/* module_param_string( intra_net, g_mcIntrNet, sizeof( g_mcIntrNet ), 0 );
module_param_named( innet_msk, g_uiIntraNetMask, int, 0 ); */

static int __init moddips_mod_init( void )
{
	int iRetVal = 0;
	printk( KERN_INFO MOD_NAME "module started\n" );

	gs_sHookOps.hook = hook_fn;
	gs_sHookOps.hooknum = NF_INET_PRE_ROUTING;
	gs_sHookOps.pf = PF_INET;
	gs_sHookOps.priority = NF_IP_PRI_FIRST;

	iRetVal = nf_register_net_hook( & init_net, & gs_sHookOps );

	return iRetVal;
}

static void __exit moddips_mod_exit( void )
{
	nf_unregister_net_hook( & init_net, & gs_sHookOps );
	printk( KERN_INFO MOD_NAME "module stopped: it has got '%u' ipsec packets\n", gs_uiItGotIPSEC );
}

static unsigned int hook_fn( void * priv, struct sk_buff * skb, const struct nf_hook_state * state )
{
	unsigned int uiRetVal = NF_ACCEPT;
	struct iphdr * psIPHdr = ip_hdr( skb );

	do {
		if( NULL != psIPHdr ) {
		} else {
			break;
		}
		if( 4 == psIPHdr->version ) {	/* IPv4 */
		} else {
			break;
		}
		if( 5 == psIPHdr->ihl ) {	/* no ip parameters */
			break;
		} else {			/* to do analize ip parameters */
			size_t s = psIPHdr->ihl * 4;
			unsigned char * pucVal = ((unsigned char *)psIPHdr);
			size_t i;
			size_t op_size = 0;
			for( i = 20; i < s; i += op_size ) {
				if(  pucVal[ i ] != 130 && pucVal[ i ] != 133 ) { /* there is nothing interesting here */
				} else {
					++ gs_uiItGotIPSEC;
					if( 0 != gs_uiItGotIPSEC % 100 ) {
			                } else {
                        			printk( KERN_INFO MOD_NAME "it has got '%u' ipsec packets\n", gs_uiItGotIPSEC );
					}
				}
				op_size = pucVal[ i + 1 ];
				if( 0 != op_size ) {
				} else {
					break;
				}
			}
		}
	} while( 0 );

	return uiRetVal;
}

module_init( moddips_mod_init );
module_exit( moddips_mod_exit );
