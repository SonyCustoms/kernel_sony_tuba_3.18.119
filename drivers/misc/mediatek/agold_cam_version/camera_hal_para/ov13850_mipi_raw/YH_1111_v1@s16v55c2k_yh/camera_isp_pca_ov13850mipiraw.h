/* Copyright Statement:
 *
 * This software/firmware and related documentation ("MediaTek Software") are
 * protected under relevant copyright laws. The information contained herein
 * is confidential and proprietary to MediaTek Inc. and/or its licensors.
 * Without the prior written permission of MediaTek inc. and/or its licensors,
 * any reproduction, modification, use or disclosure of MediaTek Software,
 * and information contained herein, in whole or in part, shall be strictly prohibited.
 */
/* MediaTek Inc. (C) 2010. All rights reserved.
 *
 * BY OPENING THIS FILE, RECEIVER HEREBY UNEQUIVOCALLY ACKNOWLEDGES AND AGREES
 * THAT THE SOFTWARE/FIRMWARE AND ITS DOCUMENTATIONS ("MEDIATEK SOFTWARE")
 * RECEIVED FROM MEDIATEK AND/OR ITS REPRESENTATIVES ARE PROVIDED TO RECEIVER ON
 * AN "AS-IS" BASIS ONLY. MEDIATEK EXPRESSLY DISCLAIMS ANY AND ALL WARRANTIES,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE OR NONINFRINGEMENT.
 * NEITHER DOES MEDIATEK PROVIDE ANY WARRANTY WHATSOEVER WITH RESPECT TO THE
 * SOFTWARE OF ANY THIRD PARTY WHICH MAY BE USED BY, INCORPORATED IN, OR
 * SUPPLIED WITH THE MEDIATEK SOFTWARE, AND RECEIVER AGREES TO LOOK ONLY TO SUCH
 * THIRD PARTY FOR ANY WARRANTY CLAIM RELATING THERETO. RECEIVER EXPRESSLY ACKNOWLEDGES
 * THAT IT IS RECEIVER'S SOLE RESPONSIBILITY TO OBTAIN FROM ANY THIRD PARTY ALL PROPER LICENSES
 * CONTAINED IN MEDIATEK SOFTWARE. MEDIATEK SHALL ALSO NOT BE RESPONSIBLE FOR ANY MEDIATEK
 * SOFTWARE RELEASES MADE TO RECEIVER'S SPECIFICATION OR TO CONFORM TO A PARTICULAR
 * STANDARD OR OPEN FORUM. RECEIVER'S SOLE AND EXCLUSIVE REMEDY AND MEDIATEK'S ENTIRE AND
 * CUMULATIVE LIABILITY WITH RESPECT TO THE MEDIATEK SOFTWARE RELEASED HEREUNDER WILL BE,
 * AT MEDIATEK'S OPTION, TO REVISE OR REPLACE THE MEDIATEK SOFTWARE AT ISSUE,
 * OR REFUND ANY SOFTWARE LICENSE FEES OR SERVICE CHARGE PAID BY RECEIVER TO
 * MEDIATEK FOR SUCH MEDIATEK SOFTWARE AT ISSUE.
 *
 * The following software/firmware and/or related documentation ("MediaTek Software")
 * have been modified by MediaTek Inc. All revisions are subject to any receiver's
 * applicable license agreements with MediaTek Inc.
 */

/********************************************************************************************
 *     LEGAL DISCLAIMER
 *
 *     (Header of MediaTek Software/Firmware Release or Documentation)
 *
 *     BY OPENING OR USING THIS FILE, BUYER HEREBY UNEQUIVOCALLY ACKNOWLEDGES AND AGREES
 *     THAT THE SOFTWARE/FIRMWARE AND ITS DOCUMENTATIONS ("MEDIATEK SOFTWARE") RECEIVED
 *     FROM MEDIATEK AND/OR ITS REPRESENTATIVES ARE PROVIDED TO BUYER ON AN "AS-IS" BASIS
 *     ONLY. MEDIATEK EXPRESSLY DISCLAIMS ANY AND ALL WARRANTIES, EXPRESS OR IMPLIED,
 *     INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR
 *     A PARTICULAR PURPOSE OR NONINFRINGEMENT. NEITHER DOES MEDIATEK PROVIDE ANY WARRANTY
 *     WHATSOEVER WITH RESPECT TO THE SOFTWARE OF ANY THIRD PARTY WHICH MAY BE USED BY,
 *     INCORPORATED IN, OR SUPPLIED WITH THE MEDIATEK SOFTWARE, AND BUYER AGREES TO LOOK
 *     ONLY TO SUCH THIRD PARTY FOR ANY WARRANTY CLAIM RELATING THERETO. MEDIATEK SHALL ALSO
 *     NOT BE RESPONSIBLE FOR ANY MEDIATEK SOFTWARE RELEASES MADE TO BUYER'S SPECIFICATION
 *     OR TO CONFORM TO A PARTICULAR STANDARD OR OPEN FORUM.
 *
 *     BUYER'S SOLE AND EXCLUSIVE REMEDY AND MEDIATEK'S ENTIRE AND CUMULATIVE LIABILITY WITH
 *     RESPECT TO THE MEDIATEK SOFTWARE RELEASED HEREUNDER WILL BE, AT MEDIATEK'S OPTION,
TO REVISE OR REPLACE THE MEDIATEK SOFTWARE AT ISSUE, OR REFUND ANY SOFTWARE LICENSE
 *     FEES OR SERVICE CHARGE PAID BY BUYER TO MEDIATEK FOR SUCH MEDIATEK SOFTWARE AT ISSUE.
 *
 *     THE TRANSACTION CONTEMPLATED HEREUNDER SHALL BE CONSTRUED IN ACCORDANCE WITH THE LAWS
 *     OF THE STATE OF CALIFORNIA, USA, EXCLUDING ITS CONFLICT OF LAWS PRINCIPLES.
 ************************************************************************************************/

/*******************************************************************************
*   ISP_NVRAM_PCA_STRUCT
********************************************************************************/
Slider:{
    value:{// low middle high
               0,    0,   0,   0,   0,   0
    }
},
Config:{
    set:{//00
        0x00000000, 0x00000000
    }
}, 
PCA_LUTS:{
    lut_lo:{    // low
        //y_gain sat_gain hue_shift reserved
        {0x0, 0xa, 0x0, 0x0}, //  0
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, // 10
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, // 20
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, // 30
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, // 40
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x2, 0x0}, //
        {0x0, 0xa, 0x2, 0x0}, // 50
        {0x0, 0xa, 0x4, 0x0}, //
        {0x0, 0xa, 0x4, 0x0}, //
        {0x0, 0xa, 0x6, 0x0}, //
        {0x0, 0xa, 0x6, 0x0}, //
        {0x0, 0xa, 0x8, 0x0}, //
        {0x0, 0xa, 0x8, 0x0}, //
        {0x0, 0xa, 0xa, 0x0}, //
        {0x0, 0xa, 0xa, 0x0}, //
        {0x0, 0xa, 0xa, 0x0}, //
        {0x0, 0xa, 0x8, 0x0}, // 60
        {0x0, 0xa, 0x8, 0x0}, //
        {0x0, 0xa, 0x6, 0x0}, //
        {0x0, 0xa, 0x6, 0x0}, //
        {0x0, 0xa, 0x4, 0x0}, //
        {0x0, 0xa, 0x4, 0x0}, //
        {0x0, 0xa, 0x2, 0x0}, //
        {0x0, 0xa, 0x2, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, // 70
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x2, 0x0}, //
        {0x0, 0xa, 0x4, 0x0}, // 80
        {0x0, 0xa, 0x6, 0x0}, //
        {0x0, 0xa, 0x8, 0x0}, //
        {0x0, 0xa, 0xa, 0x0}, //
        {0x0, 0xa, 0xc, 0x0}, //
        {0x0, 0xa, 0xe, 0x0}, //
        {0x0, 0xa, 0x10, 0x0}, //
        {0x0, 0xa, 0x12, 0x0}, //
        {0x0, 0xc, 0x14, 0x0}, //
        {0x0, 0x10, 0x14, 0x0}, //
        {0x0, 0x12, 0x12, 0x0}, // 90
        {0x0, 0x16, 0x10, 0x0}, //
        {0x0, 0x18, 0xe, 0x0}, //
        {0x0, 0x1c, 0xc, 0x0}, //
        {0x0, 0x1e, 0xa, 0x0}, //
        {0x0, 0x22, 0x8, 0x0}, //
        {0x0, 0x24, 0x6, 0x0}, //
        {0x0, 0x28, 0x4, 0x0}, //
        {0x0, 0x2a, 0x2, 0x0}, //
        {0x0, 0x2e, 0x2, 0x0}, //
        {0x0, 0x30, 0x6, 0x0}, //100
        {0x0, 0x34, 0x8, 0x0}, //
        {0x0, 0x36, 0xc, 0x0}, //
        {0x0, 0x3a, 0xe, 0x0}, //
        {0x0, 0x3c, 0x10, 0x0}, //
        {0x0, 0x40, 0x12, 0x0}, //
        {0x0, 0x42, 0x14, 0x0}, //
        {0x0, 0x46, 0x16, 0x0}, //
        {0x0, 0x48, 0x18, 0x0}, //
        {0x0, 0x4c, 0x1a, 0x0}, //
        {0x0, 0x4e, 0x1c, 0x0}, //110
        {0x0, 0x4c, 0x1e, 0x0}, //
        {0x0, 0x48, 0x1c, 0x0}, //
        {0x0, 0x46, 0x1a, 0x0}, //
        {0x0, 0x42, 0x18, 0x0}, //
        {0x0, 0x40, 0x16, 0x0}, //
        {0x0, 0x3c, 0x14, 0x0}, //
        {0x0, 0x3a, 0x12, 0x0}, //
        {0x0, 0x36, 0x10, 0x0}, //
        {0x0, 0x34, 0xe, 0x0}, //
        {0x0, 0x30, 0xc, 0x0}, //120
        {0x0, 0x2e, 0x8, 0x0}, //
        {0x0, 0x2a, 0x6, 0x0}, //
        {0x0, 0x28, 0x2, 0x0}, //
        {0x0, 0x24, 0x0, 0x0}, //
        {0x0, 0x22, 0x0, 0x0}, //
        {0x0, 0x1e, 0x0, 0x0}, //
        {0x0, 0x1c, 0x0, 0x0}, //
        {0x0, 0x18, 0x0, 0x0}, //
        {0x0, 0x16, 0x0, 0x0}, //
        {0x0, 0x12, 0x0, 0x0}, //130
        {0x0, 0x10, 0x0, 0x0}, //
        {0x0, 0xc, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //140
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //150
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //160
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //170
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0} //
    }, 
    lut_md:{    //  middle
        //y_gain sat_gain hue_shift reserved
        {0x0, 0xa, 0x0, 0x0}, //  0
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, // 10
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, // 20
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, // 30
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, // 40
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x2, 0x0}, //
        {0x0, 0xa, 0x2, 0x0}, // 50
        {0x0, 0xa, 0x4, 0x0}, //
        {0x0, 0xa, 0x4, 0x0}, //
        {0x0, 0xa, 0x6, 0x0}, //
        {0x0, 0xa, 0x6, 0x0}, //
        {0x0, 0xa, 0x8, 0x0}, //
        {0x0, 0xa, 0x8, 0x0}, //
        {0x0, 0xa, 0xa, 0x0}, //
        {0x0, 0xa, 0xa, 0x0}, //
        {0x0, 0xa, 0xa, 0x0}, //
        {0x0, 0xa, 0x8, 0x0}, // 60
        {0x0, 0xa, 0x8, 0x0}, //
        {0x0, 0xa, 0x6, 0x0}, //
        {0x0, 0xa, 0x6, 0x0}, //
        {0x0, 0xa, 0x4, 0x0}, //
        {0x0, 0xa, 0x4, 0x0}, //
        {0x0, 0xa, 0x2, 0x0}, //
        {0x0, 0xa, 0x2, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, // 70
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x2, 0x0}, //
        {0x0, 0xa, 0x4, 0x0}, // 80
        {0x0, 0xa, 0x6, 0x0}, //
        {0x0, 0xa, 0x8, 0x0}, //
        {0x0, 0xa, 0xa, 0x0}, //
        {0x0, 0xa, 0xc, 0x0}, //
        {0x0, 0xa, 0xe, 0x0}, //
        {0x0, 0xa, 0x10, 0x0}, //
        {0x0, 0xa, 0x12, 0x0}, //
        {0x0, 0xc, 0x14, 0x0}, //
        {0x0, 0x10, 0x14, 0x0}, //
        {0x0, 0x12, 0x12, 0x0}, // 90
        {0x0, 0x16, 0x10, 0x0}, //
        {0x0, 0x18, 0xe, 0x0}, //
        {0x0, 0x1c, 0xc, 0x0}, //
        {0x0, 0x1e, 0xa, 0x0}, //
        {0x0, 0x22, 0x8, 0x0}, //
        {0x0, 0x24, 0x6, 0x0}, //
        {0x0, 0x28, 0x4, 0x0}, //
        {0x0, 0x2a, 0x2, 0x0}, //
        {0x0, 0x2e, 0x2, 0x0}, //
        {0x0, 0x30, 0x6, 0x0}, //100
        {0x0, 0x34, 0x8, 0x0}, //
        {0x0, 0x36, 0xc, 0x0}, //
        {0x0, 0x3a, 0xe, 0x0}, //
        {0x0, 0x3c, 0x10, 0x0}, //
        {0x0, 0x40, 0x12, 0x0}, //
        {0x0, 0x42, 0x14, 0x0}, //
        {0x0, 0x46, 0x16, 0x0}, //
        {0x0, 0x48, 0x18, 0x0}, //
        {0x0, 0x4c, 0x1a, 0x0}, //
        {0x0, 0x4e, 0x1c, 0x0}, //110
        {0x0, 0x4c, 0x1e, 0x0}, //
        {0x0, 0x48, 0x1c, 0x0}, //
        {0x0, 0x46, 0x1a, 0x0}, //
        {0x0, 0x42, 0x18, 0x0}, //
        {0x0, 0x40, 0x16, 0x0}, //
        {0x0, 0x3c, 0x14, 0x0}, //
        {0x0, 0x3a, 0x12, 0x0}, //
        {0x0, 0x36, 0x10, 0x0}, //
        {0x0, 0x34, 0xe, 0x0}, //
        {0x0, 0x30, 0xc, 0x0}, //120
        {0x0, 0x2e, 0x8, 0x0}, //
        {0x0, 0x2a, 0x6, 0x0}, //
        {0x0, 0x28, 0x2, 0x0}, //
        {0x0, 0x24, 0x0, 0x0}, //
        {0x0, 0x22, 0x0, 0x0}, //
        {0x0, 0x1e, 0x0, 0x0}, //
        {0x0, 0x1c, 0x0, 0x0}, //
        {0x0, 0x18, 0x0, 0x0}, //
        {0x0, 0x16, 0x0, 0x0}, //
        {0x0, 0x12, 0x0, 0x0}, //130
        {0x0, 0x10, 0x0, 0x0}, //
        {0x0, 0xc, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //140
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //150
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //160
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //170
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0} //
    },
    lut_hi:{    //  high
        //y_gain sat_gain hue_shift reserved
                {0x0, 0xa, 0x0, 0x0}, //  0
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, // 10
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, // 20
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, // 30
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, // 40
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x2, 0x0}, //
        {0x0, 0xa, 0x2, 0x0}, // 50
        {0x0, 0xa, 0x4, 0x0}, //
        {0x0, 0xa, 0x4, 0x0}, //
        {0x0, 0xa, 0x6, 0x0}, //
        {0x0, 0xa, 0x6, 0x0}, //
        {0x0, 0xa, 0x8, 0x0}, //
        {0x0, 0xa, 0x8, 0x0}, //
        {0x0, 0xa, 0xa, 0x0}, //
        {0x0, 0xa, 0xa, 0x0}, //
        {0x0, 0xa, 0xa, 0x0}, //
        {0x0, 0xa, 0x8, 0x0}, // 60
        {0x0, 0xa, 0x8, 0x0}, //
        {0x0, 0xa, 0x6, 0x0}, //
        {0x0, 0xa, 0x6, 0x0}, //
        {0x0, 0xa, 0x4, 0x0}, //
        {0x0, 0xa, 0x4, 0x0}, //
        {0x0, 0xa, 0x2, 0x0}, //
        {0x0, 0xa, 0x2, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, // 70
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x2, 0x0}, //
        {0x0, 0xa, 0x4, 0x0}, // 80
        {0x0, 0xa, 0x6, 0x0}, //
        {0x0, 0xa, 0x8, 0x0}, //
        {0x0, 0xa, 0xa, 0x0}, //
        {0x0, 0xa, 0xc, 0x0}, //
        {0x0, 0xa, 0xe, 0x0}, //
        {0x0, 0xa, 0x10, 0x0}, //
        {0x0, 0xa, 0x12, 0x0}, //
        {0x0, 0xc, 0x14, 0x0}, //
        {0x0, 0x10, 0x14, 0x0}, //
        {0x0, 0x12, 0x12, 0x0}, // 90
        {0x0, 0x16, 0x10, 0x0}, //
        {0x0, 0x18, 0xe, 0x0}, //
        {0x0, 0x1c, 0xc, 0x0}, //
        {0x0, 0x1e, 0xa, 0x0}, //
        {0x0, 0x22, 0x8, 0x0}, //
        {0x0, 0x24, 0x6, 0x0}, //
        {0x0, 0x28, 0x4, 0x0}, //
        {0x0, 0x2a, 0x2, 0x0}, //
        {0x0, 0x2e, 0x2, 0x0}, //
        {0x0, 0x30, 0x6, 0x0}, //100
        {0x0, 0x34, 0x8, 0x0}, //
        {0x0, 0x36, 0xc, 0x0}, //
        {0x0, 0x3a, 0xe, 0x0}, //
        {0x0, 0x3c, 0x10, 0x0}, //
        {0x0, 0x40, 0x12, 0x0}, //
        {0x0, 0x42, 0x14, 0x0}, //
        {0x0, 0x46, 0x16, 0x0}, //
        {0x0, 0x48, 0x18, 0x0}, //
        {0x0, 0x4c, 0x1a, 0x0}, //
        {0x0, 0x4e, 0x1c, 0x0}, //110
        {0x0, 0x4c, 0x1e, 0x0}, //
        {0x0, 0x48, 0x1c, 0x0}, //
        {0x0, 0x46, 0x1a, 0x0}, //
        {0x0, 0x42, 0x18, 0x0}, //
        {0x0, 0x40, 0x16, 0x0}, //
        {0x0, 0x3c, 0x14, 0x0}, //
        {0x0, 0x3a, 0x12, 0x0}, //
        {0x0, 0x36, 0x10, 0x0}, //
        {0x0, 0x34, 0xe, 0x0}, //
        {0x0, 0x30, 0xc, 0x0}, //120
        {0x0, 0x2e, 0x8, 0x0}, //
        {0x0, 0x2a, 0x6, 0x0}, //
        {0x0, 0x28, 0x2, 0x0}, //
        {0x0, 0x24, 0x0, 0x0}, //
        {0x0, 0x22, 0x0, 0x0}, //
        {0x0, 0x1e, 0x0, 0x0}, //
        {0x0, 0x1c, 0x0, 0x0}, //
        {0x0, 0x18, 0x0, 0x0}, //
        {0x0, 0x16, 0x0, 0x0}, //
        {0x0, 0x12, 0x0, 0x0}, //130
        {0x0, 0x10, 0x0, 0x0}, //
        {0x0, 0xc, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //140
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //150
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //160
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //
        {0x0, 0xa, 0x0, 0x0}, //170
        {0x0, 0xa, 0xa, 0x0}, //
        {0x0, 0xa, 0x10, 0x0}, //
        {0x0, 0xa, 0x14, 0x0}, //
        {0x0, 0xa, 0x1a, 0x0}, //
        {0x0, 0xa, 0x1e, 0x0}, //
        {0x0, 0xa, 0x1a, 0x0}, //
        {0x0, 0xa, 0x14, 0x0}, //
        {0x0, 0xa, 0x10, 0x0}, //
        {0x0, 0xa, 0xa, 0x0} //
    },
    lut_lo2:{    // low2
        //y_gain sat_gain hue_shift reserved
        {   0,      0,      0,      0   }, //000
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //010
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //020
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //030
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //040
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //050
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //060
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //070
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //080
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //090
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //100
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //110
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //120
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //130
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //140
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //150
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //160
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //170
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //


    }, 
    lut_md2:{    //  middle2
        //y_gain sat_gain hue_shift reserved
        {   0,      0,      0,      0   }, //000
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //010
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //020
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //030
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //040
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //050
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //060
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //070
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //080
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //090
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //100
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //110
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //120
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //130
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //140
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //150
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //160
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //170
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //


    }, 
    lut_hi2:{    //  high2
        //y_gain sat_gain hue_shift reserved
        {   0,      0,      0,      0   }, //000
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //010
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //020
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //030
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //040
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //050
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //060
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //070
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //080
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //090
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //100
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //110
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //120
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //130
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //140
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //150
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //160
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //170
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
    },
    lut_lo3:{    // low2
        //y_gain sat_gain hue_shift reserved
        {   0,      0,      0,      0   }, //000
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //010
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //020
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //030
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //040
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //050
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //060
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //070
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //080
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //090
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //100
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //110
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //120
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //130
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //140
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //150
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //160
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //170
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //


    }, 
    lut_md3:{    //  middle2
        //y_gain sat_gain hue_shift reserved
        {   0,      0,      0,      0   }, //000
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //010
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //020
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //030
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //040
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //050
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //060
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //070
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //080
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //090
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //100
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //110
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //120
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //130
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //140
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //150
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //160
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //170
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //


    }, 
    lut_hi3:{    //  high2
        //y_gain sat_gain hue_shift reserved
        {   0,      0,      0,      0   }, //000
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //010
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //020
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //030
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //040
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //050
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //060
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //070
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //080
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //090
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //100
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //110
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //120
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //130
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //140
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //150
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //160
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //170
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
        {   0,      0,      0,      0   }, //
    }
        
}

