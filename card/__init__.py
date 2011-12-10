"""
card: Library adapted to request (U)SIM cards and other types of telco cards.
Copyright (C) 2010 Benoit Michau

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
"""

# smartcard Integrated Circuit Card library
# based on Laurent Rousseau pcsclite daemon and Jean-Daniel Aussel pyscard binding
# specificities of SIM and USIM card available


__all__ = ['utils', 'ICC', 'SIM', 'USIM', 'FS']
__version__ = '0.1.0'

