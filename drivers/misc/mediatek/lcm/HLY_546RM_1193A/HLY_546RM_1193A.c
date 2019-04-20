#define LOG_TAG "LCM"

#ifndef BUILD_LK
#include <linux/string.h>
#include <linux/kernel.h>
#endif

#include "lcm_drv.h"


#ifdef BUILD_LK
#include <platform/upmu_common.h>
#include <platform/mt_gpio.h>
#include <platform/mt_i2c.h>
#include <platform/mt_pmic.h>
#include <string.h>
#elif defined(BUILD_UBOOT)
#include <asm/arch/mt_gpio.h>
#else
/*#include <mach/mt_pm_ldo.h>*/
#ifdef CONFIG_MTK_LEGACY
#include <mach/mt_gpio.h>
#endif
#endif
#ifdef CONFIG_MTK_LEGACY
#include <cust_gpio_usage.h>
#endif
#ifndef CONFIG_FPGA_EARLY_PORTING
#if defined(CONFIG_MTK_LEGACY)
#include <cust_i2c.h>
#endif
#endif

#ifdef BUILD_LK
#define LCM_LOGI(string, args...)  dprintf(0, "[LK/"LOG_TAG"]"string, ##args)
#define LCM_LOGD(string, args...)  dprintf(1, "[LK/"LOG_TAG"]"string, ##args)
#else
#define LCM_LOGI(fmt, args...)  pr_debug("[KERNEL/"LOG_TAG"]"fmt, ##args)
#define LCM_LOGD(fmt, args...)  pr_debug("[KERNEL/"LOG_TAG"]"fmt, ##args)
#endif

#define LCM_ID_NT35695 (0xf5)

static const unsigned int BL_MIN_LEVEL = 20;
static LCM_UTIL_FUNCS lcm_util;
extern int agold_lcm_power_on(void);
extern int agold_lcm_power_down(void);

#define SET_RESET_PIN(v)	(lcm_util.set_reset_pin((v)))
#define MDELAY(n)		(lcm_util.mdelay(n))
#define UDELAY(n)		(lcm_util.udelay(n))



#define dsi_set_cmdq_V2(cmd, count, ppara, force_update) \
	lcm_util.dsi_set_cmdq_V2(cmd, count, ppara, force_update)
#define dsi_set_cmdq(pdata, queue_size, force_update) \
		lcm_util.dsi_set_cmdq(pdata, queue_size, force_update)
#define wrtie_cmd(cmd) lcm_util.dsi_write_cmd(cmd)
#define write_regs(addr, pdata, byte_nums) \
		lcm_util.dsi_write_regs(addr, pdata, byte_nums)
#define read_reg(cmd) \
	  lcm_util.dsi_dcs_read_lcm_reg(cmd)
#define read_reg_v2(cmd, buffer, buffer_size) \
		lcm_util.dsi_dcs_read_lcm_reg_v2(cmd, buffer, buffer_size)


/* static unsigned char lcd_id_pins_value = 0xFF; */
static const unsigned char LCD_MODULE_ID = 0x01;
#define FRAME_WIDTH										(1080)
#define FRAME_HEIGHT									(1920)


#define REGFLAG_DELAY		0xFFFC
#define REGFLAG_UDELAY	0xFFFB
#define REGFLAG_END_OF_TABLE	0xFFFD
#define REGFLAG_RESET_LOW	0xFFFE
#define REGFLAG_RESET_HIGH	0xFFFF



#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

struct LCM_setting_table {
	unsigned int cmd;
	unsigned char count;
	unsigned char para_list[64];
};


static struct LCM_setting_table init_setting[] = {
	{0xFF, 1, {0x01}},

	{0xFB, 1, {0x01}},

	{0x00, 1, {0x01}},

	{0x01, 1, {0x55}},

	{0x02, 1, {0x40}},

	{0x05, 1, {0x00}},

	{0x06, 1, {0x0A}},

	{0x07, 1, {0x8A}},

	{0x08, 1, {0x0C}},

	{0x0B, 1, {0x91}},

	{0x0C, 1, {0x91}},

	{0x0E, 1, {0x17}},

	{0x0F, 1, {0x10}},

	{0x11, 1, {0x22}},

	{0x13, 1, {0x03}},

	{0x14, 1, {0x94}},

	{0x15, 1, {0x1C}},

	{0x16, 1, {0x1C}},

	{0x18, 1, {0x00}},

	{0x19, 1, {0x77}},

	{0x1A, 1, {0x55}},

	{0x1B, 1, {0x13}},

	{0x1C, 1, {0x00}},

	{0x1D, 1, {0x00}},

	{0x1E, 1, {0x13}},

	{0x1F, 1, {0x00}},

	{0x23, 1, {0x00}},

	{0x24, 1, {0x00}},

	{0x25, 1, {0x00}},

	{0x26, 1, {0x00}},

	{0x27, 1, {0x00}},

	{0x28, 1, {0x00}},

	{0x35, 1, {0x00}},

	{0x66, 1, {0x00}},

	{0x58, 1, {0x82}},

	{0x59, 1, {0x02}},
	{0x5A, 1, {0x02}},
	{0x5B, 1, {0x02}},
	{0x5C, 1, {0x82}},
	{0x5D, 1, {0x82}},
	{0x5E, 1, {0x02}},
	{0x5F, 1, {0x02}},
	{0x6D, 1, {0x33}},
	{0x72, 1, {0x31}},
	{0xFF, 1, {0x05}},

	{0xFB, 1, {0x01}},

	{0x00, 1, {0x00}},

	{0x01, 1, {0x00}},

	{0x02, 1, {0x03}},

	{0x03, 1, {0x04}},

	{0x04, 1, {0x00}},

	{0x05, 1, {0x11}},

	{0x06, 1, {0x0C}},

	{0x07, 1, {0x0B}},

	{0x08, 1, {0x01}},

	{0x09, 1, {0x00}},

	{0x0A, 1, {0x18}},

	{0x0B, 1, {0x16}},

	{0x0C, 1, {0x14}},

	{0x0D, 1, {0x17}},

	{0x0E, 1, {0x15}},

	{0x0F, 1, {0x13}},

	{0x10, 1, {0x00}},

	{0x11, 1, {0x00}},

	{0x12, 1, {0x03}},

	{0x13, 1, {0x04}},

	{0x14, 1, {0x00}},

	{0x15, 1, {0x11}},

	{0x16, 1, {0x0C}},

	{0x17, 1, {0x0B}},

	{0x18, 1, {0x01}},

	{0x19, 1, {0x00}},

	{0x1A, 1, {0x18}},

	{0x1B, 1, {0x16}},

	{0x1C, 1, {0x14}},

	{0x1D, 1, {0x17}},

	{0x1E, 1, {0x15}},

	{0x1F, 1, {0x13}},

	{0x20, 1, {0x00}},

	{0x21, 1, {0x02}},

	{0x22, 1, {0x09}},

	{0x23, 1, {0x79}},

	{0x24, 1, {0x00}},

	{0x25, 1, {0xED}},

	{0x29, 1, {0x58}},

	{0x2A, 1, {0x29}},

	{0x2B, 1, {0x0A}},

	{0x2F, 1, {0x02}},

	{0x30, 1, {0x00}},

	{0x31, 1, {0x49}},

	{0x32, 1, {0x23}},

	{0x33, 1, {0x01}},

	{0x34, 1, {0x04}},

	{0x35, 1, {0x76}},

	{0x36, 1, {0x00}},

	{0x37, 1, {0x1D}},

	{0x38, 1, {0x08}},

	{0x5D, 1, {0x23}},

	{0x61, 1, {0x15}},

	{0x65, 1, {0x00}},

	{0x69, 1, {0x04}},

	{0x6C, 1, {0x55}},

	{0x7A, 1, {0x02}},

	{0x7B, 1, {0x80}},

	{0x7C, 1, {0xD8}},

	{0x7D, 1, {0x50}},

	{0x7E, 1, {0x09}},

	{0x7F, 1, {0x1F}},

	{0x81, 1, {0x06}},

	{0x82, 1, {0x02}},

	{0x8A, 1, {0x33}},

	{0x93, 1, {0x06}},

	{0x94, 1, {0x06}},

	{0x9B, 1, {0x0F}},

	{0xA4, 1, {0x0F}},

	{0xEA, 1, {0xFF}},

	{0xEB, 1, {0x27}},

	//{0xEC, 1, {0x01}},

	{0xC5, 1, {0x01}},

	{0xE7, 1, {0x80}},
	{0xFF, 1, {0x00}},
	//{0x35, 1, {0x00}},

	//{0x44, 1, {0x03}},

	//{0x45, 1, {0xC0}},

	{0xD3, 1, {0x08}},

	{0xD4, 1, {0x08}},

	{0x11, 0,{0x00}},

	{REGFLAG_DELAY, 120, {}},

	{0x29, 0,{0x00}},
	{REGFLAG_DELAY, 50, {}},
	{REGFLAG_END_OF_TABLE, 0x00, {}}	
};




static void push_table(struct LCM_setting_table *table, unsigned int count, unsigned char force_update)
{
	unsigned int i;
	unsigned cmd;

	for (i = 0; i < count; i++) {
		cmd = table[i].cmd;

		switch (cmd) {

		case REGFLAG_DELAY:
			if (table[i].count <= 10)
				MDELAY(table[i].count);
			else
				MDELAY(table[i].count);
			break;

		case REGFLAG_UDELAY:
			UDELAY(table[i].count);
			break;

		case REGFLAG_END_OF_TABLE:
			break;

		default:
			dsi_set_cmdq_V2(cmd, table[i].count, table[i].para_list, force_update);
		}
	}
}


static void lcm_set_util_funcs(const LCM_UTIL_FUNCS *util)
{
	memcpy(&lcm_util, util, sizeof(LCM_UTIL_FUNCS));
}


static void lcm_get_params(LCM_PARAMS *params)
{
	memset(params, 0, sizeof(LCM_PARAMS));

	params->type = LCM_TYPE_DSI;

	params->width = FRAME_WIDTH;
	params->height = FRAME_HEIGHT;

	params->dsi.mode = SYNC_PULSE_VDO_MODE;
	params->dsi.switch_mode = CMD_MODE;
	params->dsi.switch_mode_enable = 0;

	/* DSI */
	/* Command mode setting */
	params->dsi.LANE_NUM = LCM_FOUR_LANE;
	/* The following defined the fomat for data coming from LCD engine. */
	params->dsi.data_format.color_order = LCM_COLOR_ORDER_RGB;
	params->dsi.data_format.trans_seq = LCM_DSI_TRANS_SEQ_MSB_FIRST;
	params->dsi.data_format.padding = LCM_DSI_PADDING_ON_LSB;
	params->dsi.data_format.format = LCM_DSI_FORMAT_RGB888;

	/* Highly depends on LCD driver capability. */
	params->dsi.packet_size = 256;
	/* video mode timing */

	params->dsi.PS = LCM_PACKED_PS_24BIT_RGB888;

	params->dsi.vertical_sync_active = 10;
	params->dsi.vertical_backporch = 8;
	params->dsi.vertical_frontporch = 8;
	params->dsi.vertical_active_line = FRAME_HEIGHT;

	params->dsi.horizontal_sync_active = 15;
	params->dsi.horizontal_backporch = 20;
	params->dsi.horizontal_frontporch = 20;
	params->dsi.horizontal_active_pixel = FRAME_WIDTH;
	/* params->dsi.ssc_disable = 1; */
	params->dsi.PLL_CLOCK = 380;	/* this value must be in MTK suggested table */
}



static void lcm_init(void)
{
	LCM_LOGI("lcm_init enter\n");
	agold_lcm_power_on();
	//set_gpio_lcd_enp(1);
	MDELAY(15);
	SET_RESET_PIN(1);
	MDELAY(20);
	SET_RESET_PIN(0);
	MDELAY(20);
	SET_RESET_PIN(1);
	MDELAY(120);
	push_table(init_setting, sizeof(init_setting) / sizeof(struct LCM_setting_table), 1);
}

static void lcm_resume(void)
{
	LCM_LOGI("lcm_resume enter\n");
	lcm_init();
}

static void lcm_suspend(void)
{
	LCM_LOGI("lcm_suspend enter\n");

	MDELAY(15);
	SET_RESET_PIN(1);
	MDELAY(10);
	SET_RESET_PIN(0);
	MDELAY(10);
	SET_RESET_PIN(1);
	MDELAY(150);
	agold_lcm_power_down();
	//set_gpio_lcd_enp(0);
}

static void lcm_init_power(void)
{
	LCM_LOGI("lcm_init_power enter\n");
}


LCM_DRIVER HLY_546RM_1193A_lcm_drv = {
	.name = "HLY_546RM_1193A",
	.set_util_funcs = lcm_set_util_funcs,
	.get_params = lcm_get_params,
	.init = lcm_init,
	.suspend = lcm_suspend,
	.resume = lcm_resume,
	.init_power = lcm_init_power,

};
