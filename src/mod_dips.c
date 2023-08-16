
#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

static struct nf_hook_ops gs_sPreroutingBundle;
static __thread int gs_iItGotOpt;

static int moddips_hook_init( void );
static void moddips_hook_clean( void );
static unsigned int hook_prerouting( void * priv, struct sk_buff * skb, const struct nf_hook_state * state );
static int moddips_filter( const struct iphdr * p_psIPHdr );

/* module_param_string( intra_net, g_mcIntrNet, sizeof( g_mcIntrNet ), 0 );
module_param_named( innet_msk, g_uiIntraNetMask, int, 0 ); */

int __init moddips_mod_init( void )
{
	int iRetVal = 0;
	printk( pr_fmt( "module started" ) );

	local_irq_disable();

	iRetVal = moddips_hook_init();

	return iRetVal;
}

void __exit moddips_mod_exit( void )
{
	moddips_hook_clean();
	printk( pr_fmt( "module stopped" ) );
}

static int moddips_hook_init( void )
{
	/* регистрируем функцию обработки прероутинга */
	gs_sPreroutingBundle.hook = hook_prerouting;
	/* gs_sPreroutingBundle.owner = THIS_MODULE; */
	gs_sPreroutingBundle.hooknum = NF_INET_PRE_ROUTING;
	gs_sPreroutingBundle.pf = PF_INET;
	gs_sPreroutingBundle.priority = NF_IP_PRI_FIRST;

/*	#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0) */
	nf_register_net_hook( & init_net,  & gs_sPreroutingBundle );

	return 0;
}

static void moddips_hook_clean( void )
{
	/* Удаляем из цепочки hook функцию */
/*	#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0) */
	nf_unregister_net_hook( & init_net,  & gs_sPreroutingBundle );
}

static unsigned int hook_prerouting( void * priv, struct sk_buff * skb, const struct nf_hook_state * state )
{
	int iRetVal = NF_ACCEPT;

	struct iphdr * psoIP = ip_hdr( skb );

	if( 0 == moddips_filter( psoIP ) ) {
	} else {
	}

	return iRetVal;
}

static int moddips_filter( const struct iphdr * p_psIPHdr )
{
	int iRetVal = 0;

	if( 4 == p_psIPHdr->version ) {
		/* IPv4 */
	} else {
		return 0;
	}

	if( 5 == p_psIPHdr->ihl ) {
		/* no parameters */
		return 0;
	} else {
		/* to do analize ip parameters */
		if( 0 != gs_iItGotOpt ) {
		} else {
			gs_iItGotOpt = 1;
			printk( pr_fmt( "it has ip packet with parameters occurred" ) );
		}
	}

	return iRetVal;
}

MODULE_AUTHOR( "isub <sa-bir@yandex.com>" );
MODULE_DESCRIPTION( "drop ipsec ip-packets test module" );
MODULE_LICENSE( "GPL" );
