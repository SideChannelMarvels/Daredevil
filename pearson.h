/* ===================================================================== */
/* This file is part of Daredevil                                        */
/* Daredevil is a side-channel analysis tool                             */
/* Copyright (C) 2016                                                    */
/* Original author:   Paul Bottinelli <paulbottinelli@hotmail.com>       */
/* Contributors:      Joppe Bos <joppe_bos@hotmail.com>                  */
/*                                                                       */
/* This program is free software: you can redistribute it and/or modify  */
/* it under the terms of the GNU General Public License as published by  */
/* the Free Software Foundation, either version 3 of the License, or     */
/* any later version.                                                    */
/*                                                                       */
/* This program is distributed in the hope that it will be useful,       */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of        */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         */
/* GNU General Public License for more details.                          */
/*                                                                       */
/* You should have received a copy of the GNU General Public License     */
/* along with this program.  If not, see <http://www.gnu.org/licenses/>. */
/* ===================================================================== */
#ifndef PEARSON_H
#define PEARSON_H

#include <math.h>



/* Computes the correlation between the vectors t_hypot and t_real, given the
 * precomputed values sum_* and std_dev_*, using the single pass approach. The
 * precomputed values can be calculated by the functions precomp_v_2_*.
 */
  template <class Type1, class Type2, class Type3>
Type1 pearson_v_2_2(Type3 t_hypot[], Type1 sum_hypot, Type1 std_dev_hypot, Type2 t_real[], Type1 sum_real, Type1 std_dev_real, int length)
{
  Type1 sum_prod = 0.0;

  for(int i = 0; i < length; i++) {
    sum_prod += (Type1) t_hypot[i] * (Type1) t_real[i];
  }

  return length * (( sum_prod - (sum_hypot * sum_real)/length ) /
   (std_dev_hypot * std_dev_real));

}

#endif
