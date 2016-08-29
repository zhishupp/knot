/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
/*!
 * \file
 *
 * \brief Query module interface
 *
 * The concept of query plan is simple - each query requires a finite
 * number of steps to be solved. For example IN query needs to find an answer and
 * based on the result, process authority and maybe supply additional records.
 * This can be represented by a query plan:
 * answer => { find_answer },
 * authority => { process_authority },
 * additional => { process_additional }
 *
 * The example is obvious, but if a state is passed between the callbacks,
 * same principle applies for every query processing.
 * This file provides an interface for basic query plan and more importantly
 * dynamically loaded modules that can alter query plans.
 * For a default internet zone query plan, see \file internet.h
 *
 * \addtogroup query_processing
 * @{
 */

#pragma once

#include "libknot/packet/pkt.h"
#include "libknot/mm_ctx.h"

/*! @} */
