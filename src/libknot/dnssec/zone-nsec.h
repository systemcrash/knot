/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \file zone-sign.h
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief Interface for generating of NSEC/NSEC3 records in zone.
 *
 * \addtogroup dnssec
 * @{
 */

#ifndef _KNOT_DNSSEC_ZONE_NSEC_H_
#define _KNOT_DNSSEC_ZONE_NSEC_H_

#include "libknot/updates/changesets.h"
#include "libknot/zone/zone-contents.h"

/*!
 * \brief Create NSEC or NSEC3 chain in the zone.
 *
 * \param zone       Zone for which the NSEC(3) chain will be created.
 * \param changeset  Changeset into which the changes will be added.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_zone_create_nsec_chain(const knot_zone_contents_t *zone,
				knot_changeset_t *changeset);

/*!
 * \brief Connect regular and NSEC3 nodes in the zone.
 *
 * \note No need to call this function after 'knot_zone_create_nsec_chain'.
 * \note Exits succesfully if NSEC3 is not enabled.
 * \note Skips nodes with missing related NSEC3 nodes.
 *
 * \param zone  Zone for which the operation is performed.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_zone_connect_nsec_nodes(knot_zone_contents_t *zone);

#endif // _KNOT_DNSSEC_ZONE_NSEC_H_

/*! @} */
