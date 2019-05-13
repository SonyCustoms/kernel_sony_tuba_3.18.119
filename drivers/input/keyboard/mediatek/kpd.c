/*
 * Copyright (C) 2010 MediaTek, Inc.
 *
 * Author: Terry Chang <terry.chang@mediatek.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include "kpd.h"
#include <linux/wakelock.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/clk.h>
#include <linux/gpio.h>

#define KPD_NAME	"mtk-kpd"
#define MTK_KP_WAKESOURCE	/* this is for auto set wake up source */

/**/
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/switch.h>
/**/
#include <linux/workqueue.h>
/**/
/**/

#if defined(CONFIG_POWERKEY_FORCECRASH)
#define PWK_DUMP
#ifdef __aarch64__
#undef BUG
#define BUG() *((unsigned *)0xaed) = 0xDEAD
#endif
#endif

void __iomem *kp_base;
static unsigned int kp_irqnr;
struct input_dev *kpd_input_dev;
static bool kpd_suspend;
static int kpd_show_hw_keycode = 1;
static int kpd_show_register = 1;
unsigned long call_status = 2;
struct wake_lock kpd_suspend_lock;	/* For suspend usage */

/*for kpd_memory_setting() function*/
static u16 kpd_keymap[KPD_NUM_KEYS];
static u16 kpd_keymap_state[KPD_NUM_MEMS];
#if (defined(CONFIG_ARCH_MT8173) || defined(CONFIG_ARCH_MT8163) || defined(CONFIG_ARCH_MT8167))
static struct wake_lock pwrkey_lock;
#endif
/***********************************/

/* for slide QWERTY */
#if KPD_HAS_SLIDE_QWERTY
static void kpd_slide_handler(unsigned long data);
static DECLARE_TASKLET(kpd_slide_tasklet, kpd_slide_handler, 0);
static u8 kpd_slide_state = !KPD_SLIDE_POLARITY;
#endif
struct keypad_dts_data kpd_dts_data;
/* for Power key using EINT */
#ifdef CONFIG_KPD_PWRKEY_USE_EINT
static void kpd_pwrkey_handler(unsigned long data);
static DECLARE_TASKLET(kpd_pwrkey_tasklet, kpd_pwrkey_handler, 0);
#endif

/* for keymap handling */
static void kpd_keymap_handler(unsigned long data);
static DECLARE_TASKLET(kpd_keymap_tasklet, kpd_keymap_handler, 0);

//Camera key bring up -S
/* for camera key setting*/
#define KPD_CAM_FOCUS_MAP KEY_FOCUS
#define KPD_CAM_CAPTURE_MAP KEY_CAMERA
#define KPD_CAMERA_NUM 	2
//#define KPD_VOLUP 104
#define GPIO_CEI_FOCUS_KEY		79
#define GPIO_CEI_CAPTURE_KEY		62
//#define camerakeydebounce 	250
//static u8 camera_focus_state = IRQF_TRIGGER_FALLING;
//static u8 camera_capture_state = IRQF_TRIGGER_FALLING;
static unsigned int focuskey_irq, capturekey_irq;
static unsigned int gpiopin, camerakeydebounce, focuskey_eint_type, capturekey_eint_type;
static u16 kpd_camerakeymap[KPD_CAMERA_NUM] = {KPD_CAM_FOCUS_MAP , KPD_CAM_CAPTURE_MAP};
static void camera_focus_eint_func(unsigned long data);
static void camera_capture_eint_func(unsigned long data);
static DECLARE_TASKLET(kpd_camera_focus_tasklet, camera_focus_eint_func, 0);
static DECLARE_TASKLET(kpd_camera_capture_tasklet, camera_capture_eint_func, 0);
//Camera key bring up -E

/**/
/* for hall sensor setting */
#define CEI_HALL_OUT 107
static void hall_out_handler(unsigned long data);
static DECLARE_TASKLET(hall_out_tasklet, hall_out_handler, 0);
static int old_INT_stat = 1;
static struct switch_dev sdev;
struct pinctrl *pinctrl_hall;
struct pinctrl_state *pins_hall_default;
static unsigned int hall_irqnr;
struct device_node *hall_irq_node;
/**/
static struct delayed_work hall_work;
static struct mutex hall_state_mutex;
/**/
/**/

/*********************************************************************/
static void kpd_memory_setting(void);

/*********************************************************************/
static int kpd_pdrv_probe(struct platform_device *pdev);
static int kpd_pdrv_remove(struct platform_device *pdev);
#ifndef USE_EARLY_SUSPEND
static int kpd_pdrv_suspend(struct platform_device *pdev, pm_message_t state);
static int kpd_pdrv_resume(struct platform_device *pdev);
#endif

static const struct of_device_id kpd_of_match[] = {
	{.compatible = "mediatek,mt6580-keypad"},
	{.compatible = "mediatek,mt6570-keypad"},
	{.compatible = "mediatek,mt6735-keypad"},
	{.compatible = "mediatek,mt6755-keypad"},
	{.compatible = "mediatek,mt6757-keypad"},
	{.compatible = "mediatek,mt8173-keypad"},
	{.compatible = "mediatek,mt6797-keypad"},
	{.compatible = "mediatek,mt8163-keypad"},
	{.compatible = "mediatek,mt8167-keypad"},
	{.compatible = "mediatek,mt8127-keypad"},
	{.compatible = "mediatek,mt2701-keypad"},
	{.compatible = "mediatek,mt7623-keypad"},
	{.compatible = "mediatek,elbrus-keypad"},
	{},
};

static struct platform_driver kpd_pdrv = {
	.probe = kpd_pdrv_probe,
	.remove = kpd_pdrv_remove,
#ifndef USE_EARLY_SUSPEND
	.suspend = kpd_pdrv_suspend,
	.resume = kpd_pdrv_resume,
#endif
	.driver = {
		   .name = KPD_NAME,
		   .owner = THIS_MODULE,
		   .of_match_table = kpd_of_match,
		   },
};

/********************************************************************/
static void kpd_memory_setting(void)
{
	kpd_init_keymap(kpd_keymap);
	kpd_init_keymap_state(kpd_keymap_state);
}

/*****************for kpd auto set wake up source*************************/

static ssize_t kpd_store_call_state(struct device_driver *ddri, const char *buf, size_t count)
{
	int ret;

	ret = kstrtoul(buf, 10, &call_status);
	if (ret) {
		kpd_print("kpd call state: Invalid values\n");
		return -EINVAL;
	}

	switch (call_status) {
	case 1:
		kpd_print("kpd call state: Idle state!\n");
		break;
	case 2:
		kpd_print("kpd call state: ringing state!\n");
		break;
	case 3:
		kpd_print("kpd call state: active or hold state!\n");
		break;

	default:
		kpd_print("kpd call state: Invalid values\n");
		break;
	}
	return count;
}

static ssize_t kpd_show_call_state(struct device_driver *ddri, char *buf)
{
	ssize_t res;

	res = snprintf(buf, PAGE_SIZE, "%ld\n", call_status);
	return res;
}

static DRIVER_ATTR(kpd_call_state, S_IWUSR | S_IRUGO, kpd_show_call_state, kpd_store_call_state);

static struct driver_attribute *kpd_attr_list[] = {
	&driver_attr_kpd_call_state,
};

/*----------------------------------------------------------------------------*/
static int kpd_create_attr(struct device_driver *driver)
{
	int idx, err = 0;
	int num = (int)(sizeof(kpd_attr_list) / sizeof(kpd_attr_list[0]));

	if (driver == NULL)
		return -EINVAL;

	for (idx = 0; idx < num; idx++) {
		err = driver_create_file(driver, kpd_attr_list[idx]);
		if (err) {
			kpd_info("driver_create_file (%s) = %d\n", kpd_attr_list[idx]->attr.name, err);
			break;
		}
	}
	return err;
}

/*----------------------------------------------------------------------------*/
static int kpd_delete_attr(struct device_driver *driver)
{
	int idx, err = 0;
	int num = (int)(sizeof(kpd_attr_list) / sizeof(kpd_attr_list[0]));

	if (!driver)
		return -EINVAL;

	for (idx = 0; idx < num; idx++)
		driver_remove_file(driver, kpd_attr_list[idx]);

	return err;
}

/*----------------------------------------------------------------------------*/
/********************************************************************************************/
/************************************************************************************************************************************************/
/* for autotest */
#if KPD_AUTOTEST
static const u16 kpd_auto_keymap[] = {
	KEY_MENU,
	KEY_HOME, KEY_BACK,
	KEY_CALL, KEY_ENDCALL,
	KEY_VOLUMEUP, KEY_VOLUMEDOWN,
	KEY_FOCUS, KEY_CAMERA,
};
#endif
/* for AEE manual dump */
#define AEE_VOLUMEUP_BIT	0
#define AEE_VOLUMEDOWN_BIT	1
#define AEE_DELAY_TIME		15
/* enable volup + voldown was pressed 5~15 s Trigger aee manual dump */
#define AEE_ENABLE_5_15		1
static struct hrtimer aee_timer;
static unsigned long aee_pressed_keys;
static bool aee_timer_started;

#if AEE_ENABLE_5_15
#define AEE_DELAY_TIME_5S	5
static struct hrtimer aee_timer_5s;
static bool aee_timer_5s_started;
static bool flags_5s;
#endif

#ifdef PWK_DUMP
#define AEE_POWERKEY_BIT 2
static struct hrtimer aee_timer_powerkey_30s;
static bool aee_timer_powerkey_30s_started;
#define AEE_DELAY_TIME_30S 30
#endif

static inline void kpd_update_aee_state(void)
{
	if (aee_pressed_keys == ((1 << AEE_VOLUMEUP_BIT) | (1 << AEE_VOLUMEDOWN_BIT))) {
		/* if volumeup and volumedown was pressed the same time then start the time of ten seconds */
		aee_timer_started = true;

#if AEE_ENABLE_5_15
		aee_timer_5s_started = true;
		hrtimer_start(&aee_timer_5s, ktime_set(AEE_DELAY_TIME_5S, 0), HRTIMER_MODE_REL);
#endif
		hrtimer_start(&aee_timer, ktime_set(AEE_DELAY_TIME, 0), HRTIMER_MODE_REL);
		kpd_print("aee_timer started\n");
	} else {
		/*
		  * hrtimer_cancel - cancel a timer and wait for the handler to finish.
		  * Returns:
		  * 0 when the timer was not active.
		  * 1 when the timer was active.
		 */
		if (aee_timer_started) {
			if (hrtimer_cancel(&aee_timer)) {
				kpd_print("try to cancel hrtimer\n");
#if AEE_ENABLE_5_15
				if (flags_5s) {
					kpd_print("Pressed Volup + Voldown5s~15s then trigger aee manual dump.\n");
					/*ZH CHEN*/
					/*aee_kernel_reminding("manual dump", "Trigger Vol Up +Vol Down 5s");*/
				}
#endif

			}
#if AEE_ENABLE_5_15
			flags_5s = false;
#endif
			aee_timer_started = false;
			kpd_print("aee_timer canceled\n");
		}
#if AEE_ENABLE_5_15
		/*
		  * hrtimer_cancel - cancel a timer and wait for the handler to finish.
		  * Returns:
		  * 0 when the timer was not active.
		  * 1 when the timer was active.
		 */
		if (aee_timer_5s_started) {
			if (hrtimer_cancel(&aee_timer_5s))
				kpd_print("try to cancel hrtimer (5s)\n");
			aee_timer_5s_started = false;
			kpd_print("aee_timer canceled (5s)\n");
		}
#endif
	}
#ifdef PWK_DUMP
		if (aee_pressed_keys == 1<<AEE_POWERKEY_BIT) {
			printk("aee_timer_powerkey_30s_started  true  \n");
			aee_timer_powerkey_30s_started = true;
			hrtimer_start(&aee_timer_powerkey_30s,ktime_set(AEE_DELAY_TIME_30S, 0),HRTIMER_MODE_REL);
		} else {
			if (aee_timer_powerkey_30s_started) {
				if (hrtimer_cancel(&aee_timer_powerkey_30s)) {
					kpd_print("try to cancel aee_timer_powerkey_30s  \n");
				}
				aee_timer_powerkey_30s_started = false;
				printk("aee_timer_powerkey_30s_started  false \n");
				kpd_print("aee_timer aee_timer_powerkey_30s stop \n");
			}
		}
#endif
}

static void kpd_aee_handler(u32 keycode, u16 pressed)
{
	if (pressed) {
		if (keycode == KEY_VOLUMEUP)
			__set_bit(AEE_VOLUMEUP_BIT, &aee_pressed_keys);
		else if (keycode == KEY_VOLUMEDOWN)
			__set_bit(AEE_VOLUMEDOWN_BIT, &aee_pressed_keys);
#ifdef PWK_DUMP
		else if (keycode == KEY_POWER) {
			printk(KPD_SAY "kpd_aee_handler  KEY_POWER  __set_bit \n");
			__set_bit(AEE_POWERKEY_BIT, &aee_pressed_keys);
		}
#endif
		else
			return;
		kpd_update_aee_state();
	} else {
		if (keycode == KEY_VOLUMEUP)
			__clear_bit(AEE_VOLUMEUP_BIT, &aee_pressed_keys);
		else if (keycode == KEY_VOLUMEDOWN)
			__clear_bit(AEE_VOLUMEDOWN_BIT, &aee_pressed_keys);
#ifdef PWK_DUMP
		else if (keycode == KEY_POWER) {
			printk(KPD_SAY "kpd_aee_handler  KEY_POWER  __clear_bit \n");
			__clear_bit(AEE_POWERKEY_BIT, &aee_pressed_keys);
		}
#endif
		else
			return;
		kpd_update_aee_state();
	}
}

static enum hrtimer_restart aee_timer_func(struct hrtimer *timer)
{
	/* kpd_info("kpd: vol up+vol down AEE manual dump!\n"); */
	/* aee_kernel_reminding("manual dump ", "Triggered by press KEY_VOLUMEUP+KEY_VOLUMEDOWN"); */
	/*ZH CHEN*/
	/*aee_trigger_kdb();*/
	return HRTIMER_NORESTART;
}

#if AEE_ENABLE_5_15
static enum hrtimer_restart aee_timer_5s_func(struct hrtimer *timer)
{

	/* kpd_info("kpd: vol up+vol down AEE manual dump timer 5s !\n"); */
	flags_5s = true;
	return HRTIMER_NORESTART;
}
#endif

#ifdef PWK_DUMP
static enum hrtimer_restart aee_timer_30s_func(struct hrtimer *timer)
{
	pr_err("*************FORCE CRASH***************");
	printk("in aee_timer_30s_func \n");
	BUG();
	return HRTIMER_NORESTART;
}
#endif

/************************************************************************/
#if KPD_HAS_SLIDE_QWERTY
static void kpd_slide_handler(unsigned long data)
{
	bool slid;
	u8 old_state = kpd_slide_state;

	kpd_slide_state = !kpd_slide_state;
	slid = (kpd_slide_state == !!KPD_SLIDE_POLARITY);
	/* for SW_LID, 1: lid open => slid, 0: lid shut => closed */
	input_report_switch(kpd_input_dev, SW_LID, slid);
	input_sync(kpd_input_dev);
	kpd_print("report QWERTY = %s\n", slid ? "slid" : "closed");

	if (old_state)
		mt_set_gpio_pull_select(GPIO_QWERTYSLIDE_EINT_PIN, 0);
	else
		mt_set_gpio_pull_select(GPIO_QWERTYSLIDE_EINT_PIN, 1);
	/* for detecting the return to old_state */
	mt65xx_eint_set_polarity(KPD_SLIDE_EINT, old_state);
	mt65xx_eint_unmask(KPD_SLIDE_EINT);
}

static void kpd_slide_eint_handler(void)
{
	tasklet_schedule(&kpd_slide_tasklet);
}
#endif

#ifdef CONFIG_KPD_PWRKEY_USE_EINT
static void kpd_pwrkey_handler(unsigned long data)
{
	kpd_pwrkey_handler_hal(data);
}

static void kpd_pwrkey_eint_handler(void)
{
	tasklet_schedule(&kpd_pwrkey_tasklet);
}
#endif
/*********************************************************************/

/*********************************************************************/
#ifdef CONFIG_KPD_PWRKEY_USE_PMIC
void kpd_pwrkey_pmic_handler(unsigned long pressed)
{
	kpd_print("Power Key generate, pressed=%ld\n", pressed);
	if (!kpd_input_dev) {
		kpd_print("KPD input device not ready\n");
		return;
	}
	kpd_pmic_pwrkey_hal(pressed);
#if (defined(CONFIG_ARCH_MT8173) || defined(CONFIG_ARCH_MT8163))
	if (pressed) /* keep the lock while the button in held pushed */
		wake_lock(&pwrkey_lock);
	else /* keep the lock for extra 500ms after the button is released */
		wake_lock_timeout(&pwrkey_lock, HZ/2);
#endif
#ifdef PWK_DUMP
	printk(KPD_SAY "Power Key generate, pressed=%ld enter kpd_aee_handler \n", pressed);
	kpd_aee_handler(KEY_POWER, pressed);
#endif
}
#endif

void kpd_pmic_rstkey_handler(unsigned long pressed)
{
	kpd_print("PMIC reset Key generate, pressed=%ld\n", pressed);
	if (!kpd_input_dev) {
		kpd_print("KPD input device not ready\n");
		return;
	}
	kpd_pmic_rstkey_hal(pressed);
#ifdef KPD_PMIC_RSTKEY_MAP
	kpd_aee_handler(KPD_PMIC_RSTKEY_MAP, pressed);
#endif
}

/*********************************************************************/

/*********************************************************************/
static void kpd_keymap_handler(unsigned long data)
{
	int i, j;
	bool pressed;
	u16 new_state[KPD_NUM_MEMS], change, mask;
	u16 hw_keycode, linux_keycode;

	kpd_get_keymap_state(new_state);

	wake_lock_timeout(&kpd_suspend_lock, HZ / 2);

	for (i = 0; i < KPD_NUM_MEMS; i++) {
		change = new_state[i] ^ kpd_keymap_state[i];
		if (!change)
			continue;

		for (j = 0; j < 16; j++) {
			mask = 1U << j;
			if (!(change & mask))
				continue;

			hw_keycode = (i << 4) + j;
			/* bit is 1: not pressed, 0: pressed */
			pressed = !(new_state[i] & mask);
			if (kpd_show_hw_keycode)
				kpd_print("(%s) HW keycode = %u\n", pressed ? "pressed" : "released", hw_keycode);
			BUG_ON(hw_keycode >= KPD_NUM_KEYS);
			linux_keycode = kpd_keymap[hw_keycode];
			if (unlikely(linux_keycode == 0)) {
				kpd_print("Linux keycode = 0\n");
				continue;
			}
			kpd_aee_handler(linux_keycode, pressed);

			input_report_key(kpd_input_dev, linux_keycode, pressed);
			input_sync(kpd_input_dev);
			kpd_print("report Linux keycode = %u\n", linux_keycode);
		}
	}

	memcpy(kpd_keymap_state, new_state, sizeof(new_state));
	kpd_print("save new keymap state\n");
	enable_irq(kp_irqnr);
}

static irqreturn_t kpd_irq_handler(int irq, void *dev_id)
{
	/* use _nosync to avoid deadlock */
	disable_irq_nosync(kp_irqnr);
	tasklet_schedule(&kpd_keymap_tasklet);
	return IRQ_HANDLED;
}

/*********************************************************************/

/*****************************************************************************************/
long kpd_dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	/* void __user *uarg = (void __user *)arg; */

	switch (cmd) {
#if KPD_AUTOTEST
	case PRESS_OK_KEY:	/* KPD_AUTOTEST disable auto test setting to resolve CR ALPS00464496 */
		if (test_bit(KEY_OK, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] PRESS OK KEY!!\n");
			input_report_key(kpd_input_dev, KEY_OK, 1);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support OK KEY!!\n");
		}
		break;
	case RELEASE_OK_KEY:
		if (test_bit(KEY_OK, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] RELEASE OK KEY!!\n");
			input_report_key(kpd_input_dev, KEY_OK, 0);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support OK KEY!!\n");
		}
		break;
	case PRESS_MENU_KEY:
		if (test_bit(KEY_MENU, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] PRESS MENU KEY!!\n");
			input_report_key(kpd_input_dev, KEY_MENU, 1);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support MENU KEY!!\n");
		}
		break;
	case RELEASE_MENU_KEY:
		if (test_bit(KEY_MENU, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] RELEASE MENU KEY!!\n");
			input_report_key(kpd_input_dev, KEY_MENU, 0);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support MENU KEY!!\n");
		}

		break;
	case PRESS_UP_KEY:
		if (test_bit(KEY_UP, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] PRESS UP KEY!!\n");
			input_report_key(kpd_input_dev, KEY_UP, 1);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support UP KEY!!\n");
		}
		break;
	case RELEASE_UP_KEY:
		if (test_bit(KEY_UP, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] RELEASE UP KEY!!\n");
			input_report_key(kpd_input_dev, KEY_UP, 0);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support UP KEY!!\n");
		}
		break;
	case PRESS_DOWN_KEY:
		if (test_bit(KEY_DOWN, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] PRESS DOWN KEY!!\n");
			input_report_key(kpd_input_dev, KEY_DOWN, 1);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support DOWN KEY!!\n");
		}
		break;
	case RELEASE_DOWN_KEY:
		if (test_bit(KEY_DOWN, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] RELEASE DOWN KEY!!\n");
			input_report_key(kpd_input_dev, KEY_DOWN, 0);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support DOWN KEY!!\n");
		}
		break;
	case PRESS_LEFT_KEY:
		if (test_bit(KEY_LEFT, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] PRESS LEFT KEY!!\n");
			input_report_key(kpd_input_dev, KEY_LEFT, 1);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support LEFT KEY!!\n");
		}
		break;
	case RELEASE_LEFT_KEY:
		if (test_bit(KEY_LEFT, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] RELEASE LEFT KEY!!\n");
			input_report_key(kpd_input_dev, KEY_LEFT, 0);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support LEFT KEY!!\n");
		}
		break;

	case PRESS_RIGHT_KEY:
		if (test_bit(KEY_RIGHT, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] PRESS RIGHT KEY!!\n");
			input_report_key(kpd_input_dev, KEY_RIGHT, 1);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support RIGHT KEY!!\n");
		}
		break;
	case RELEASE_RIGHT_KEY:
		if (test_bit(KEY_RIGHT, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] RELEASE RIGHT KEY!!\n");
			input_report_key(kpd_input_dev, KEY_RIGHT, 0);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support RIGHT KEY!!\n");
		}
		break;
	case PRESS_HOME_KEY:
		if (test_bit(KEY_HOME, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] PRESS HOME KEY!!\n");
			input_report_key(kpd_input_dev, KEY_HOME, 1);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support HOME KEY!!\n");
		}
		break;
	case RELEASE_HOME_KEY:
		if (test_bit(KEY_HOME, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] RELEASE HOME KEY!!\n");
			input_report_key(kpd_input_dev, KEY_HOME, 0);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support HOME KEY!!\n");
		}
		break;
	case PRESS_BACK_KEY:
		if (test_bit(KEY_BACK, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] PRESS BACK KEY!!\n");
			input_report_key(kpd_input_dev, KEY_BACK, 1);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support BACK KEY!!\n");
		}
		break;
	case RELEASE_BACK_KEY:
		if (test_bit(KEY_BACK, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] RELEASE BACK KEY!!\n");
			input_report_key(kpd_input_dev, KEY_BACK, 0);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support BACK KEY!!\n");
		}
		break;
	case PRESS_CALL_KEY:
		if (test_bit(KEY_CALL, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] PRESS CALL KEY!!\n");
			input_report_key(kpd_input_dev, KEY_CALL, 1);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support CALL KEY!!\n");
		}
		break;
	case RELEASE_CALL_KEY:
		if (test_bit(KEY_CALL, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] RELEASE CALL KEY!!\n");
			input_report_key(kpd_input_dev, KEY_CALL, 0);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support CALL KEY!!\n");
		}
		break;

	case PRESS_ENDCALL_KEY:
		if (test_bit(KEY_ENDCALL, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] PRESS ENDCALL KEY!!\n");
			input_report_key(kpd_input_dev, KEY_ENDCALL, 1);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support ENDCALL KEY!!\n");
		}
		break;
	case RELEASE_ENDCALL_KEY:
		if (test_bit(KEY_ENDCALL, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] RELEASE ENDCALL KEY!!\n");
			input_report_key(kpd_input_dev, KEY_ENDCALL, 0);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support ENDCALL KEY!!\n");
		}
		break;
	case PRESS_VLUP_KEY:
		if (test_bit(KEY_VOLUMEUP, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] PRESS VOLUMEUP KEY!!\n");
			input_report_key(kpd_input_dev, KEY_VOLUMEUP, 1);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support VOLUMEUP KEY!!\n");
		}
		break;
	case RELEASE_VLUP_KEY:
		if (test_bit(KEY_VOLUMEUP, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] RELEASE VOLUMEUP KEY!!\n");
			input_report_key(kpd_input_dev, KEY_VOLUMEUP, 0);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support VOLUMEUP KEY!!\n");
		}
		break;
	case PRESS_VLDOWN_KEY:
		if (test_bit(KEY_VOLUMEDOWN, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] PRESS VOLUMEDOWN KEY!!\n");
			input_report_key(kpd_input_dev, KEY_VOLUMEDOWN, 1);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support VOLUMEDOWN KEY!!\n");
		}
		break;
	case RELEASE_VLDOWN_KEY:
		if (test_bit(KEY_VOLUMEDOWN, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] RELEASE VOLUMEDOWN KEY!!\n");
			input_report_key(kpd_input_dev, KEY_VOLUMEDOWN, 0);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support VOLUMEDOWN KEY!!\n");
		}
		break;
	case PRESS_FOCUS_KEY:
		if (test_bit(KEY_FOCUS, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] PRESS FOCUS KEY!!\n");
			input_report_key(kpd_input_dev, KEY_FOCUS, 1);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support FOCUS KEY!!\n");
		}
		break;
	case RELEASE_FOCUS_KEY:
		if (test_bit(KEY_FOCUS, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] RELEASE FOCUS KEY!!\n");
			input_report_key(kpd_input_dev, KEY_FOCUS, 0);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support RELEASE KEY!!\n");
		}
		break;
	case PRESS_CAMERA_KEY:
		if (test_bit(KEY_CAMERA, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] PRESS CAMERA KEY!!\n");
			input_report_key(kpd_input_dev, KEY_CAMERA, 1);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support CAMERA KEY!!\n");
		}
		break;
	case RELEASE_CAMERA_KEY:
		if (test_bit(KEY_CAMERA, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] RELEASE CAMERA KEY!!\n");
			input_report_key(kpd_input_dev, KEY_CAMERA, 0);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support CAMERA KEY!!\n");
		}
		break;
	case PRESS_POWER_KEY:
		if (test_bit(KEY_POWER, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] PRESS POWER KEY!!\n");
			input_report_key(kpd_input_dev, KEY_POWER, 1);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support POWER KEY!!\n");
		}
		break;
	case RELEASE_POWER_KEY:
		if (test_bit(KEY_POWER, kpd_input_dev->keybit)) {
			kpd_print("[AUTOTEST] RELEASE POWER KEY!!\n");
			input_report_key(kpd_input_dev, KEY_POWER, 0);
			input_sync(kpd_input_dev);
		} else {
			kpd_print("[AUTOTEST] Not Support POWER KEY!!\n");
		}
		break;
#endif

	case SET_KPD_KCOL:
		kpd_auto_test_for_factorymode();	/* API 3 for kpd factory mode auto-test */
		kpd_print("[kpd_auto_test_for_factorymode] test performed!!\n");
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

int kpd_dev_open(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations kpd_dev_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = kpd_dev_ioctl,
	.open = kpd_dev_open,
};

/*********************************************************************/
static struct miscdevice kpd_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = KPD_NAME,
	.fops = &kpd_dev_fops,
};

static int kpd_open(struct input_dev *dev)
{
	kpd_slide_qwerty_init();	/* API 1 for kpd slide qwerty init settings */
	return 0;
}

/*********************************************************************/
/**/
static int hall_out_status_show(struct seq_file *s, void *unused)
{
	int state;
	state = __gpio_get_value(CEI_HALL_OUT);
	seq_printf(s, "%d\n", state);
	return 0;
}
static int hall_out_status_open(struct inode *inode, struct file *file)
{
	return single_open(file, hall_out_status_show, NULL);
}
static const struct file_operations hall_out_status_fops = {
	.owner	= THIS_MODULE,
	.open	= hall_out_status_open,
	.read		= seq_read,
	.llseek	= seq_lseek,
	.release	= single_release,
};

/**/
static void hall_work_func(struct work_struct *work)
{
	int state;
	state = __gpio_get_value(CEI_HALL_OUT);

	kpd_print("[Keypad] state = %d ,  old_INT_stat = %d \n", (int)state, old_INT_stat);

	mutex_lock(&hall_state_mutex);
	if(old_INT_stat != state)
	{
		if(state == 1)
		{
			kpd_print("[Keypad] hall_out  (0 -> 1) OPEN\n");
		}
		else
		{
			kpd_print("[Keypad] hall_out  (1 -> 0) CLOSE\n");
		}
		old_INT_stat = state;
		switch_set_state((struct switch_dev *)&sdev, state);
	}
	mutex_unlock(&hall_state_mutex);
}
/**/

static void hall_out_handler(unsigned long data)
{
/**/
#if 0
	int state;
	state = __gpio_get_value(CEI_HALL_OUT);

	kpd_print("[Keypad] state = %d ,  old_INT_stat = %d \n", (int)state, old_INT_stat);

	if(old_INT_stat != state)
	{
		if(state == 1)
		{
			kpd_print("[Keypad] hall_out  (0 -> 1) OPEN\n");
		}
		else
		{
			kpd_print("[Keypad] hall_out  (1 -> 0) CLOSE\n");
		}
		old_INT_stat = state;
		switch_set_state((struct switch_dev *)&sdev, state);
	}
#endif
	kpd_print("[Keypad] %s() Enter\n", __FUNCTION__);
	schedule_delayed_work(&hall_work, 0);
/**/
	enable_irq(hall_irqnr);
}

static irqreturn_t hall_interrupt_handler(int irq, void *dev)
{
	/* use _nosync to avoid deadlock */
	disable_irq_nosync(hall_irqnr);

	kpd_print("[Keypad] %s() Enter\n", __FUNCTION__);
	tasklet_schedule(&hall_out_tasklet);
	return IRQ_HANDLED;
}

int hall_gpio_eint_setup(struct platform_device *pdev)
{
	int err;
	int irq_flags;
	kpd_print("[Keypad] %s , enter\n", __FUNCTION__ );

	/* get pinctrl */
	pinctrl_hall = devm_pinctrl_get(&pdev->dev);
	if (IS_ERR_OR_NULL(pinctrl_hall)) {
		kpd_print("[Keypad] %s , Failed to get pinctrl\n", __FUNCTION__ );
		goto hall_gpio_pinctrl_err;
	}

	pins_hall_default = pinctrl_lookup_state(pinctrl_hall, "cei_hall_out");
	if (IS_ERR_OR_NULL(pins_hall_default)) {
		kpd_print("[Keypad] %s , Failed to look up cei_hall_out state\n", __FUNCTION__ );
		goto hall_gpio_pinctrl_err;
	}

	/* request gpio */
	err = gpio_request_one(CEI_HALL_OUT, GPIOF_DIR_IN, "hall_sensor_irq");
	if (err) {
		kpd_print("[Keypad] %s , unable to request gpio %d\n", __FUNCTION__ , CEI_HALL_OUT);
		goto hall_gpio_pinctrl_err;
	}

	/* select pinctrl */
	err = pinctrl_select_state(pinctrl_hall, pins_hall_default);
	if (err) {
		kpd_print("[Keypad] %s , Can't select pinctrl default state\n", __FUNCTION__ );
		return err;
	}

	/* request irq */
	hall_irq_node = of_find_compatible_node(NULL, NULL, "mediatek, cei_hall_out-eint");
	if (hall_irq_node) {
		hall_irqnr = irq_of_parse_and_map(hall_irq_node, 0);
		kpd_print("[Keypad] %s , hall_irqnr = %d\n", __FUNCTION__ , hall_irqnr );
		if (!hall_irqnr) {
			kpd_print("[Keypad] %s , irq_of_parse_and_map fail!!\n", __FUNCTION__ );
			goto free_gpio;
		}

		irq_flags = IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING | IRQF_ONESHOT;
		//if ( request_irq(hall_irqnr, hall_interrupt_handler, IRQF_TRIGGER_NONE, "cei_hall_out-eint", NULL) ) {
		if ( request_irq(hall_irqnr, hall_interrupt_handler, irq_flags, "cei_hall_out-eint", NULL) ) {
			kpd_print("[Keypad] %s , IRQ LINE NOT AVAILABLE!!\n", __FUNCTION__ );
			goto free_gpio;
		}

		enable_irq(hall_irqnr);
	}
	else {
		kpd_print("[Keypad] %s , cannot find cei_hall_out-eint node\n", __FUNCTION__ );
		goto free_gpio;
	}

	kpd_print("[Keypad] %s , exit - Success\n", __FUNCTION__ );
	return 0;

free_gpio:
	gpio_free(CEI_HALL_OUT);
hall_gpio_pinctrl_err:
	kpd_print("[Keypad] %s , exit - Fail\n", __FUNCTION__ );
	return -EINVAL;
}
/**/
/*********************************************************************/

void kpd_get_dts_info(struct device_node *node)
{
	int ret;
	of_property_read_u32(node, "mediatek,kpd-key-debounce", &kpd_dts_data.kpd_key_debounce);
	of_property_read_u32(node, "mediatek,kpd-sw-pwrkey", &kpd_dts_data.kpd_sw_pwrkey);
	of_property_read_u32(node, "mediatek,kpd-hw-pwrkey", &kpd_dts_data.kpd_hw_pwrkey);
	of_property_read_u32(node, "mediatek,kpd-sw-rstkey", &kpd_dts_data.kpd_sw_rstkey);
	of_property_read_u32(node, "mediatek,kpd-hw-rstkey", &kpd_dts_data.kpd_hw_rstkey);
	of_property_read_u32(node, "mediatek,kpd-use-extend-type", &kpd_dts_data.kpd_use_extend_type);
	of_property_read_u32(node, "mediatek,kpd-pwrkey-eint-gpio", &kpd_dts_data.kpd_pwrkey_eint_gpio);
	of_property_read_u32(node, "mediatek,kpd-pwrkey-gpio-din", &kpd_dts_data.kpd_pwrkey_gpio_din);
	of_property_read_u32(node, "mediatek,kpd-hw-dl-key1", &kpd_dts_data.kpd_hw_dl_key1);
	of_property_read_u32(node, "mediatek,kpd-hw-dl-key2", &kpd_dts_data.kpd_hw_dl_key2);
	of_property_read_u32(node, "mediatek,kpd-hw-dl-key3", &kpd_dts_data.kpd_hw_dl_key3);
	of_property_read_u32(node, "mediatek,kpd-hw-recovery-key", &kpd_dts_data.kpd_hw_recovery_key);
	of_property_read_u32(node, "mediatek,kpd-hw-factory-key", &kpd_dts_data.kpd_hw_factory_key);
	of_property_read_u32(node, "mediatek,kpd-hw-map-num", &kpd_dts_data.kpd_hw_map_num);
	ret = of_property_read_u32_array(node, "mediatek,kpd-hw-init-map", kpd_dts_data.kpd_hw_init_map,
		kpd_dts_data.kpd_hw_map_num);

	if (ret) {
		kpd_print("kpd-hw-init-map was not defined in dts.\n");
		memset(kpd_dts_data.kpd_hw_init_map, 0, sizeof(kpd_dts_data.kpd_hw_init_map));
	}

	kpd_print("key-debounce = %d, sw-pwrkey = %d, hw-pwrkey = %d, hw-rstkey = %d, sw-rstkey = %d\n",
		  kpd_dts_data.kpd_key_debounce, kpd_dts_data.kpd_sw_pwrkey, kpd_dts_data.kpd_hw_pwrkey,
		  kpd_dts_data.kpd_hw_rstkey, kpd_dts_data.kpd_sw_rstkey);
}
//Camera key bring up -S
/*********************************************************************/
static irqreturn_t kpd_camera_focus_eint_handler(int irq, void *dev_id)
{
	disable_irq_nosync(focuskey_irq);
	tasklet_schedule(&kpd_camera_focus_tasklet);
	return IRQ_HANDLED;
}

static irqreturn_t kpd_camera_capture_eint_handler(int irq, void *dev_id)
{
	disable_irq_nosync(capturekey_irq);
	tasklet_schedule(&kpd_camera_capture_tasklet);
	return IRQ_HANDLED;

}

static int kpd_camerakey_setup_eint(void)
{
	int err = 0;
	struct device_node *node;
	u32 ints[2] = { 0, 0 };
	u32 ints1[2] = { 0, 0 };
	int cmkey_irq_flags;
	cmkey_irq_flags = IRQ_TYPE_LEVEL_LOW | IRQ_TYPE_LEVEL_HIGH | IRQF_ONESHOT;
	//Focus key Setting.
	node = of_find_compatible_node(NULL, NULL, "mediatek,CEI_CAMERA_FOCUS-eint");
	if (node) {
		of_property_read_u32_array(node, "debounce", ints, ARRAY_SIZE(ints));
		of_property_read_u32_array(node, "interrupts", ints1, ARRAY_SIZE(ints1));
		gpiopin = ints[0];
		camerakeydebounce = ints[1];
		focuskey_eint_type = ints1[1];
		//gpio_request(gpiopin, "foucskey");
		gpio_set_debounce(gpiopin, 300);
		//gpio_free(gpiopin);
		focuskey_irq = irq_of_parse_and_map(node, 0);
		err = request_irq(focuskey_irq, kpd_camera_focus_eint_handler, cmkey_irq_flags, "focuskey-eint", NULL);
		//err = request_irq(focuskey_irq, kpd_camera_focus_eint_handler, irq_flags, "focuskey-eint", NULL);
		if (err > 0) {
			kpd_print("[Keypad] FOUCS KEY EINT IRQ LINE NOT AVAILABLE\n");
		} else {
			kpd_print("[keypad] FOUCS KEY set EINT finished, focuskey_irq=%d, headsetdebounce=%d\n",
				     focuskey_irq, camerakeydebounce);
		}
	} else {
		kpd_print("[Keypad]%s can't find compatible node\n", __func__);
	}
	//Capture key Setting.
		node = of_find_compatible_node(NULL, NULL, "mediatek,CEI_CAMERA_CAPTURE-eint");
	if (node) {
		of_property_read_u32_array(node, "debounce", ints, ARRAY_SIZE(ints));
		of_property_read_u32_array(node, "interrupts", ints1, ARRAY_SIZE(ints1));
		gpiopin = ints[0];
		camerakeydebounce = ints[1];
		capturekey_eint_type = ints1[1];
		//gpio_request(gpiopin, "capturekey");
	       gpio_set_debounce(gpiopin, 300);
		//gpio_free(gpiopin);
		capturekey_irq = irq_of_parse_and_map(node, 0);
		err = request_irq(capturekey_irq, kpd_camera_capture_eint_handler, cmkey_irq_flags, "capturekey-eint", NULL);
		//err = request_irq(capturekey_irq, kpd_camera_capture_eint_handler, irq_flags, "capturekey-eint", NULL);
		if (err > 0) {
			kpd_print("[Keypad] CAPTURE KEY EINT IRQ LINE NOT AVAILABLE\n");
		} else {
			kpd_print("[keypad] CAPTURE KEY set EINT finished, capturekey_irq=%d, headsetdebounce=%d\n",
				     capturekey_irq, camerakeydebounce);
		}
	} else {
		kpd_print("[Keypad]%s can't find compatible node\n", __func__);
	}
		return 0;
}


static void camera_focus_eint_func(unsigned long data)
{
	bool pressed = false;
	u8 old_state;

#if 1
	if(focuskey_eint_type == IRQ_TYPE_LEVEL_LOW)
	{
               old_state = (1);
	}
	else
	{
	       old_state = (0);
	}

	kpd_print("[Keypad]old_state = %d\n",(int)old_state);

       if(focuskey_eint_type == IRQ_TYPE_LEVEL_LOW)
       {
		pressed=true;
		irq_set_irq_type(focuskey_irq, IRQ_TYPE_LEVEL_HIGH);
		focuskey_eint_type = IRQ_TYPE_LEVEL_HIGH;
       }
       else
       {
		pressed=false;
		irq_set_irq_type(focuskey_irq, IRQ_TYPE_LEVEL_LOW);
		focuskey_eint_type = IRQ_TYPE_LEVEL_LOW;
       }
	//kpd_info("[Keypad]revert camera_focus_state = %d \n",(int)camera_capture_state);
	printk(KPD_SAY "(%s) [Keypad] HW keycode = %u\n",
				       pressed ? "pressed" : "released", KPD_CAM_FOCUS_MAP);
	//kpd_print("[Keypad]pressed = %d\n",(int)pressed);
	input_report_key(kpd_input_dev, KPD_CAM_FOCUS_MAP, pressed);
	input_sync(kpd_input_dev);
	enable_irq(focuskey_irq);

#endif

}
static void camera_capture_eint_func(unsigned long data)
{
	bool pressed = false;
	u8 old_state;

	wake_lock_timeout(&kpd_suspend_lock, HZ / 2);
#if 1
	if(capturekey_eint_type == IRQ_TYPE_LEVEL_LOW)
	{
		old_state = (1);
	}
	else
	{
		old_state = (0);
	}

	kpd_print("[Keypad]old_state = %d\n",(int)old_state);

	if(capturekey_eint_type == IRQ_TYPE_LEVEL_LOW)
       {
		pressed=true;
		irq_set_irq_type(capturekey_irq, IRQ_TYPE_LEVEL_HIGH);
		capturekey_eint_type = IRQ_TYPE_LEVEL_HIGH;
       }
       else
       {
		pressed=false;
		irq_set_irq_type(capturekey_irq, IRQ_TYPE_LEVEL_LOW);
		capturekey_eint_type = IRQ_TYPE_LEVEL_LOW;
       }
	//kpd_info("[Keypad]revert camera_capture_state = %d \n",(int)camera_capture_state);
	printk(KPD_SAY "(%s) [Keypad] HW keycode = %u\n",
				       pressed ? "pressed" : "released", KPD_CAM_CAPTURE_MAP);
	//kpd_print("[Keypad]pressed = %d\n",(int)pressed);
	input_report_key(kpd_input_dev, KPD_CAM_CAPTURE_MAP, pressed);
	input_sync(kpd_input_dev);
	enable_irq(capturekey_irq);

#endif

}
//Camera key bring up -E
static int kpd_pdrv_probe(struct platform_device *pdev)
{

	int i, r;
	int err = 0;
	struct clk *kpd_clk = NULL;
	//Keypad porting - S
  #if 1
	struct pinctrl *pinctrl1;
	struct pinctrl_state *pins_default, *pins_eint_int;
  #endif
        //Keypad porting - E
	kpd_info("Keypad probe start!!!\n");

	/*kpd-clk should be control by kpd driver, not depend on default clock state*/
	kpd_clk = devm_clk_get(&pdev->dev, "kpd-clk");
	if (!IS_ERR(kpd_clk)) {
		int ret_prepare, ret_enable;

		ret_prepare = clk_prepare(kpd_clk);
		if (ret_prepare)
			kpd_print("clk_prepare returned %d\n", ret_prepare);
		ret_enable = clk_enable(kpd_clk);
		if (ret_enable)
			kpd_print("clk_enable returned %d\n", ret_prepare);
	} else {
		kpd_print("get kpd-clk fail, but not return, maybe kpd-clk is set by ccf.\n");
	}

	kp_base = of_iomap(pdev->dev.of_node, 0);
	if (!kp_base) {
		kpd_info("KP iomap failed\n");
		return -ENODEV;
	};

	kp_irqnr = irq_of_parse_and_map(pdev->dev.of_node, 0);
	if (!kp_irqnr) {
		kpd_info("KP get irqnr failed\n");
		return -ENODEV;
	}
	kpd_info("kp base: 0x%p, addr:0x%p,  kp irq: %d\n", kp_base, &kp_base, kp_irqnr);
	/* initialize and register input device (/dev/input/eventX) */
	kpd_input_dev = input_allocate_device();
	if (!kpd_input_dev) {
		kpd_print("input allocate device fail.\n");
		return -ENOMEM;
	}

	kpd_input_dev->name = KPD_NAME;
	kpd_input_dev->id.bustype = BUS_HOST;
	kpd_input_dev->id.vendor = 0x2454;
	kpd_input_dev->id.product = 0x6500;
	kpd_input_dev->id.version = 0x0010;
	kpd_input_dev->open = kpd_open;

	kpd_get_dts_info(pdev->dev.of_node);

#if (defined(CONFIG_ARCH_MT8173) || defined(CONFIG_ARCH_MT8163) || defined(CONFIG_ARCH_MT8167))
	wake_lock_init(&pwrkey_lock, WAKE_LOCK_SUSPEND, "PWRKEY");
#endif

	/* fulfill custom settings */
	kpd_memory_setting();

	__set_bit(EV_KEY, kpd_input_dev->evbit);
//keypad bring up - S

#if 1  //for volume down key
  pinctrl1 = devm_pinctrl_get(&pdev->dev);
	if (IS_ERR(pinctrl1)) {
		err = PTR_ERR(pinctrl1);
		dev_err(&pdev->dev, "fwq Cannot find voldown pinctrl1!\n");
		return err;
	}

	pins_default = pinctrl_lookup_state(pinctrl1, "default");
	if (IS_ERR(pins_default)) {
		err = PTR_ERR(pins_default);
		dev_err(&pdev->dev, "fwq Cannot find voldown pinctrl default!\n");
	}

	pins_eint_int = pinctrl_lookup_state(pinctrl1, "kpd_pins_eint");
	if (IS_ERR(pins_eint_int)) {
		err = PTR_ERR(pins_eint_int);
		dev_err(&pdev->dev, "fwq Cannot find voldown pinctrl state_eint_int!\n");
		return err;
	}
#endif
	#if 0
	gpio_request(KPD_VOLUP , "KPD_KCOL1");
	gpio_direction_input(KPD_VOLUP);
	gpio_free(KPD_VOLUP);
	#endif
	pinctrl_select_state(pinctrl1, pins_eint_int);
//keypad bring up - E
	/**/
	err = hall_gpio_eint_setup(pdev);
	if (err!=0) {
		kpd_print("[Keypad] %s , hall_gpio_eint_setup failed (%d)\n", __FUNCTION__ , err );
	}

	proc_create_data("hall_out_status", 0444, NULL, &hall_out_status_fops, NULL);
	sdev.name = "hall_gpio";
	sdev.index = 0;
	sdev.state = 1;
	r = switch_dev_register(&sdev);
	if (r) {
		kpd_info("[Keypad] %s , register switch device failed (%d)\n", __FUNCTION__ , r);
		switch_dev_unregister(&sdev);
		return r;
	}
	/**/
	switch_set_state((struct switch_dev *)&sdev, 1);	// state initialization
	/**/
	/**/
	mutex_init(&hall_state_mutex);
	INIT_DELAYED_WORK(&hall_work, hall_work_func);
	/**/
	/**/

#if defined(CONFIG_KPD_PWRKEY_USE_EINT) || defined(CONFIG_KPD_PWRKEY_USE_PMIC)
	__set_bit(kpd_dts_data.kpd_sw_pwrkey, kpd_input_dev->keybit);
	kpd_keymap[8] = 0;
#endif
	if (!kpd_dts_data.kpd_use_extend_type) {
		for (i = 17; i < KPD_NUM_KEYS; i += 9)	/* only [8] works for Power key */
			kpd_keymap[i] = 0;
	}
	for (i = 0; i < KPD_NUM_KEYS; i++) {
		if (kpd_keymap[i] != 0)
			__set_bit(kpd_keymap[i], kpd_input_dev->keybit);
	}

#if KPD_AUTOTEST
	for (i = 0; i < ARRAY_SIZE(kpd_auto_keymap); i++)
		__set_bit(kpd_auto_keymap[i], kpd_input_dev->keybit);
#endif

#if KPD_HAS_SLIDE_QWERTY
	__set_bit(EV_SW, kpd_input_dev->evbit);
	__set_bit(SW_LID, kpd_input_dev->swbit);
#endif
	if (kpd_dts_data.kpd_sw_rstkey)
		__set_bit(kpd_dts_data.kpd_sw_rstkey, kpd_input_dev->keybit);
#ifdef KPD_KEY_MAP
	__set_bit(KPD_KEY_MAP, kpd_input_dev->keybit);
#endif
#ifdef CONFIG_MTK_MRDUMP_KEY
		__set_bit(KEY_RESTART, kpd_input_dev->keybit);
#endif
//Caerma key porting
#if 1
	for (i = 0; i < KPD_CAMERA_NUM; i++) {
		if (kpd_camerakeymap[i] != 0)
	__set_bit(kpd_camerakeymap[i], kpd_input_dev->keybit);
		kpd_info("[Keypad] set kpd_camerakeymap[%d]" , i);
		}
#endif
	kpd_input_dev->dev.parent = &pdev->dev;
	r = input_register_device(kpd_input_dev);
	if (r) {
		kpd_info("register input device failed (%d)\n", r);
		input_free_device(kpd_input_dev);
		return r;
	}

	/* register device (/dev/mt6575-kpd) */
	kpd_dev.parent = &pdev->dev;
	r = misc_register(&kpd_dev);
	if (r) {
		kpd_info("register device failed (%d)\n", r);
		input_unregister_device(kpd_input_dev);
		return r;
	}

	wake_lock_init(&kpd_suspend_lock, WAKE_LOCK_SUSPEND, "kpd wakelock");

	/* register IRQ and EINT */
	kpd_set_debounce(kpd_dts_data.kpd_key_debounce);
	r = request_irq(kp_irqnr, kpd_irq_handler, IRQF_TRIGGER_NONE, KPD_NAME, NULL);
	if (r) {
		kpd_info("register IRQ failed (%d)\n", r);
		misc_deregister(&kpd_dev);
		input_unregister_device(kpd_input_dev);
		return r;
	}
#ifdef CONFIG_MTK_MRDUMP_KEY
/* This func use as mrdump now, if powerky use kpd eint it need to open another API */
	mt_eint_register();
#endif
   //Camera key bring up -S
   printk("camera_key_setup_eint() START!!\n");
	kpd_camerakey_setup_eint();
	printk("camera_key_setup_eint() Done!!\n");
	//Camera key bring up -E
#ifdef CONIFG_KPD_ACCESS_PMIC_REGMAP
	/*kpd_hal access pmic registers via regmap interface*/
	err = kpd_init_pmic_regmap(pdev);
	if (err)
		kpd_print("kpd cannot get regmap, please check dts config first.\n");
#endif

#ifndef KPD_EARLY_PORTING	/*add for avoid early porting build err the macro is defined in custom file */
	long_press_reboot_function_setting();	/* /API 4 for kpd long press reboot function setting */
#endif
	hrtimer_init(&aee_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	aee_timer.function = aee_timer_func;

#if AEE_ENABLE_5_15
	hrtimer_init(&aee_timer_5s, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	aee_timer_5s.function = aee_timer_5s_func;
#endif

#ifdef PWK_DUMP
	hrtimer_init(&aee_timer_powerkey_30s, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	aee_timer_powerkey_30s.function = aee_timer_30s_func;
#endif
	err = kpd_create_attr(&kpd_pdrv.driver);
	if (err) {
		kpd_info("create attr file fail\n");
		kpd_delete_attr(&kpd_pdrv.driver);
		return err;
	}
	kpd_info("%s Done\n", __func__);
	return 0;
}

/* should never be called */
static int kpd_pdrv_remove(struct platform_device *pdev)
{
	return 0;
}

#ifndef USE_EARLY_SUSPEND
static int kpd_pdrv_suspend(struct platform_device *pdev, pm_message_t state)
{
	kpd_suspend = true;
#ifdef MTK_KP_WAKESOURCE
	if (call_status == 2) {
		kpd_print("kpd_early_suspend wake up source enable!! (%d)\n", kpd_suspend);
	} else {
		kpd_wakeup_src_setting(0);
		kpd_print("kpd_early_suspend wake up source disable!! (%d)\n", kpd_suspend);
	}
#endif
	kpd_print("suspend!! (%d)\n", kpd_suspend);
	return 0;
}

static int kpd_pdrv_resume(struct platform_device *pdev)
{
	kpd_suspend = false;
#ifdef MTK_KP_WAKESOURCE
	if (call_status == 2) {
		kpd_print("kpd_early_suspend wake up source enable!! (%d)\n", kpd_suspend);
	} else {
		kpd_print("kpd_early_suspend wake up source resume!! (%d)\n", kpd_suspend);
		kpd_wakeup_src_setting(1);
	}
#endif
	kpd_print("resume!! (%d)\n", kpd_suspend);
	return 0;
}
#else
#define kpd_pdrv_suspend	NULL
#define kpd_pdrv_resume		NULL
#endif

#ifdef USE_EARLY_SUSPEND
static void kpd_early_suspend(struct early_suspend *h)
{
	kpd_suspend = true;
#ifdef MTK_KP_WAKESOURCE
	if (call_status == 2) {
		kpd_print("kpd_early_suspend wake up source enable!! (%d)\n", kpd_suspend);
	} else {
		/* kpd_wakeup_src_setting(0); */
		kpd_print("kpd_early_suspend wake up source disable!! (%d)\n", kpd_suspend);
	}
#endif
	kpd_print("early suspend!! (%d)\n", kpd_suspend);
}

static void kpd_early_resume(struct early_suspend *h)
{
	kpd_suspend = false;
#ifdef MTK_KP_WAKESOURCE
	if (call_status == 2) {
		kpd_print("kpd_early_resume wake up source resume!! (%d)\n", kpd_suspend);
	} else {
		kpd_print("kpd_early_resume wake up source enable!! (%d)\n", kpd_suspend);
		/* kpd_wakeup_src_setting(1); */
	}
#endif
	kpd_print("early resume!! (%d)\n", kpd_suspend);
}

static struct early_suspend kpd_early_suspend_desc = {
	.level = EARLY_SUSPEND_LEVEL_BLANK_SCREEN + 1,
	.suspend = kpd_early_suspend,
	.resume = kpd_early_resume,
};
#endif

#ifdef CONFIG_MTK_SMARTBOOK_SUPPORT
#ifdef CONFIG_HAS_SBSUSPEND
static struct sb_handler kpd_sb_handler_desc = {
	.level = SB_LEVEL_DISABLE_KEYPAD,
	.plug_in = sb_kpd_enable,
	.plug_out = sb_kpd_disable,
};
#endif
#endif

static int __init kpd_mod_init(void)
{
	int r;

	r = platform_driver_register(&kpd_pdrv);
	if (r) {
		kpd_info("register driver failed (%d)\n", r);
		return r;
	}
#ifdef USE_EARLY_SUSPEND
	register_early_suspend(&kpd_early_suspend_desc);
#endif

#ifdef CONFIG_MTK_SMARTBOOK_SUPPORT
#ifdef CONFIG_HAS_SBSUSPEND
	register_sb_handler(&kpd_sb_handler_desc);
#endif
#endif

	return 0;
}

/* should never be called */
static void __exit kpd_mod_exit(void)
{
}

module_init(kpd_mod_init);
module_exit(kpd_mod_exit);

module_param(kpd_show_hw_keycode, int, 0644);
module_param(kpd_show_register, int, 0644);

MODULE_AUTHOR("yucong.xiong <yucong.xiong@mediatek.com>");
MODULE_DESCRIPTION("MTK Keypad (KPD) Driver v0.4");
MODULE_LICENSE("GPL");
