/* misc.c
 *
 * Copyright (C) 2018-2021 DesignFirst OU
 * Copyright (C) 2022 EnactTrust LTD
 *
 * This file is part of EnactTrust.
 *
 * EnactTrust is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * EnactTrust is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with EnactTrust. If not, see <https://www.gnu.org/licenses/>.
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int misc_uuid_str2bin(const char *str, size_t str_size, char *bytes, size_t size)
{
    int i, b;
    char hexstr[3];

    i = b = 0;
    while(i < str_size)
    {
        if(str[i] == '-') {
            i++;
            continue;
        }

        hexstr[0] = str[i++];
        hexstr[1] = str[i++];
        hexstr[2] = '\0';

        bytes[b++] = (char)strtol(hexstr, NULL, 16);
    }

    return b;
}
