/*
 * Copyright (C) 2015  T+A elektroakustik GmbH & Co. KG
 *
 * This file is part of DCPD.
 *
 * DCPD is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 3 as
 * published by the Free Software Foundation.
 *
 * DCPD is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with DCPD.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef DRCP_COMMAND_CODES_H
#define DRCP_COMMAND_CODES_H

#define DRCP_POWER_ON                           0x02
#define DRCP_POWER_OFF                          0x03
#define DRCP_POWER_TOGGLE                       0x04
#define DRCP_ALARM_CANCEL                       0x06
#define DRCP_ALARM_SNOOZE                       0x07
#define DRCP_SLEEP_TIMER_START                  0x08
#define DRCP_PLAYBACK_PAUSE                     0x13
#define DRCP_KEY_CAPS_LOCK_TOGGLE               0x14
#define DRCP_ACCEPT                             0x1e
#define DRCP_UPNP_START_SSDP_DISCOVERY          0x1f
#define DRCP_SCROLL_UP_MANY                     0x21
#define DRCP_SCROLL_DOWN_MANY                   0x22
#define DRCP_GOTO_LINE                          0x23
#define DRCP_GO_BACK_ONE_LEVEL                  0x25
#define DRCP_SCROLL_UP_ONE                      0x26
#define DRCP_SELECT_ITEM                        0x27
#define DRCP_SCROLL_DOWN_ONE                    0x28
#define DRCP_KEY_OK_ENTER                       0x29
#define DRCP_CANCEL_JUMP_COMMAND                0x2a
#define DRCP_KEY_EXECUTE                        0x2b
#define DRCP_FAVORITES_STORE                    0x2c
#define DRCP_FAVORITES_ADD_ITEM                 0x2d
#define DRCP_FAVORITES_REMOVE_ITEM              0x2e
#define DRCP_FAVORITES_CLEAR                    0x2f
#define DRCP_KEY_DIGIT_0                        ((uint8_t)'0')  /* 0x30 */
#define DRCP_KEY_DIGIT_1                        ((uint8_t)'1')
#define DRCP_KEY_DIGIT_2                        ((uint8_t)'2')
#define DRCP_KEY_DIGIT_3                        ((uint8_t)'3')
#define DRCP_KEY_DIGIT_4                        ((uint8_t)'4')
#define DRCP_KEY_DIGIT_5                        ((uint8_t)'5')
#define DRCP_KEY_DIGIT_6                        ((uint8_t)'6')
#define DRCP_KEY_DIGIT_7                        ((uint8_t)'7')
#define DRCP_KEY_DIGIT_8                        ((uint8_t)'8')
#define DRCP_KEY_DIGIT_9                        ((uint8_t)'9')  /* 0x39 */
#define DRCP_KEY_LETTER_A                       ((uint8_t)'A')  /* 0x41 */
#define DRCP_KEY_LETTER_B                       ((uint8_t)'B')
#define DRCP_KEY_LETTER_C                       ((uint8_t)'C')
#define DRCP_KEY_LETTER_D                       ((uint8_t)'D')
#define DRCP_KEY_LETTER_E                       ((uint8_t)'E')
#define DRCP_KEY_LETTER_F                       ((uint8_t)'F')
#define DRCP_KEY_LETTER_G                       ((uint8_t)'G')
#define DRCP_KEY_LETTER_H                       ((uint8_t)'H')
#define DRCP_KEY_LETTER_I                       ((uint8_t)'I')
#define DRCP_KEY_LETTER_J                       ((uint8_t)'J')
#define DRCP_KEY_LETTER_K                       ((uint8_t)'K')
#define DRCP_KEY_LETTER_L                       ((uint8_t)'L')
#define DRCP_KEY_LETTER_M                       ((uint8_t)'M')
#define DRCP_KEY_LETTER_N                       ((uint8_t)'N')
#define DRCP_KEY_LETTER_O                       ((uint8_t)'O')
#define DRCP_KEY_LETTER_P                       ((uint8_t)'P')
#define DRCP_KEY_LETTER_Q                       ((uint8_t)'Q')
#define DRCP_KEY_LETTER_R                       ((uint8_t)'R')
#define DRCP_KEY_LETTER_S                       ((uint8_t)'S')
#define DRCP_KEY_LETTER_T                       ((uint8_t)'T')
#define DRCP_KEY_LETTER_U                       ((uint8_t)'U')
#define DRCP_KEY_LETTER_V                       ((uint8_t)'V')
#define DRCP_KEY_LETTER_W                       ((uint8_t)'W')
#define DRCP_KEY_LETTER_X                       ((uint8_t)'X')
#define DRCP_KEY_LETTER_Y                       ((uint8_t)'Y')
#define DRCP_KEY_LETTER_Z                       ((uint8_t)'Z')  /* 0x5a */
#define DRCP_SCROLL_PAGE_UP                     0x97
#define DRCP_SCROLL_PAGE_DOWN                   0x98
#define DRCP_JUMP_TO_LETTER                     0x99
#define DRCP_BROWSE_VIEW_OPEN_SOURCE            0x9a
#define DRCP_SEARCH                             0x9b
#define DRCP_JUMP_TO_NEXT                       0x9d
#define DRCP_GOTO_INTERNET_RADIO                0xaa
#define DRCP_GOTO_FAVORITES                     0xab
#define DRCP_GOTO_HOME                          0xac
#define DRCP_VOLUME_DOWN                        0xae
#define DRCP_VOLUME_UP                          0xaf
#define DRCP_PLAYBACK_NEXT                      0xb0
#define DRCP_PLAYBACK_PREVIOUS                  0xb1
#define DRCP_PLAYBACK_STOP                      0xb2
#define DRCP_PLAYBACK_START                     0xb3
#define DRCP_PLAYBACK_SELECTED_FILE_ONESHOT     0xb4
#define DRCP_BROWSE_PLAY_VIEW_TOGGLE            0xba
#define DRCP_BROWSE_PLAY_VIEW_SET               0xbb
#define DRCP_REPEAT_MODE_TOGGLE                 0xc0
#define DRCP_FAST_WIND_FORWARD                  0xc1
#define DRCP_FAST_WIND_REVERSE                  0xc2
#define DRCP_FAST_WIND_STOP                     0xc3
#define DRCP_FAST_WIND_SET_SPEED                0xc4
#define DRCP_REPEAT_MODE_SET                    0xc6
#define DRCP_AUDIOBOOK_SET_SPEED                0xc5
#define DRCP_SHUFFLE_MODE_SET                   0xc7
#define DRCP_GOTO_CONFIGURATION                 0xdb
#define DRCP_SHUFFLE_MODE_TOGGLE                0xdc
#define DRCP_GOTO_SOURCE_SELECTION              0xde
#define DRCP_GOTO_FM_TUNER                      0xf0
#define DRCP_PLAYBACK_MUTE_TOGGLE               0xf1
#define DRCP_VIDEO_MODE_SET_NTSC                0xf4
#define DRCP_VIDEO_MODE_SET_PAL                 0xf5
#define DRCP_PLAYBACK_START_OR_RESUME           0xfa

#endif /* !DRCP_COMMAND_CODES_H */
