#!/bin/bash
#
# Copyright (c) 2006 Mellanox Technologies. All rights reserved.
#
# This Software is licensed under one of the following licenses:
#
# 1) under the terms of the "Common Public License 1.0" a copy of which is
#    available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/cpl.php.
#
# 2) under the terms of the "The BSD License" a copy of which is
#    available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/bsd-license.php.
#
# 3) under the terms of the "GNU General Public License (GPL) Version 2" a
#    copy of which is available from the Open Source Initiative, see
#    http://www.opensource.org/licenses/gpl-license.php.
#
# Licensee has the right to choose one of the above licenses.
#
# Redistributions of source code must retain the above copyright
# notice and one of the license notices.
#
# Redistributions in binary form must reproduce both the above copyright
# notice, one of the license notices in the documentation
# and/or other materials provided with the distribution.


# Execute command w/ echo and exit if it fail
ex()
{
        echo "$@"
        if ! "$@"; then
                printf "\nFailed executing $@\n\n"
                exit 1
        fi
}

# Apply patch
apply_patch()
{
        local patch=$1
        shift

        if [ -e  ${patch} ]; then
            printf "\t${patch}\n"
            if [ "${WITH_QUILT}" == "yes" ]; then
                ex $QUILT import ${patch}
                ex $QUILT push patches/${patch##*/}
            else
                if ! (patch -p1 -l < ${patch} ); then
                    echo "Failed to apply patch: ${patch}"
                    exit 1
                fi
            fi
        else
                echo File ${patch} does not exist
                return 1
        fi
        return 0
}


# Apply patches from the given directory
apply_backport_patches()
{
        local pdir=${CWD}/kernel_patches/backport/${BACKPORT_DIR}
        shift
        printf "\nApplying patches for ${BACKPORT_DIR} kernel:\n"
        if [ -d ${pdir} ]; then
                for patch in ${pdir}/*mlx4*.patch
                do
                        apply_patch ${patch}
                done
                for patch in ${pdir}/dma_mapping*.patch
                do
                        apply_patch ${patch}
                done
		for patch in ${pdir}/memtrack*.patch
		do
			apply_patch ${patch}
		done
        else
                echo ${pdir} no such directory
        fi
}

# Apply patches
patches_handle()
{
    ex mkdir -p ${CWD}/patches
    quiltrc=${CWD}/patches/quiltrc
    ex touch ${quiltrc}

cat << EOF >> ${quiltrc}
QUILT_DIFF_OPTS='-x .svn -p --ignore-matching-lines=\$Id'
QUILT_PATCH_OPTS='-l'
EOF

        QUILT="${QUILT} --quiltrc ${quiltrc}"

        # Apply backport patches
        BACKPORT_DIR=${BACKPORT_DIR:-$(${CWD}/scripts/get_backport_dir.sh ${KVERSION})}
        if [ -n "${BACKPORT_DIR}" ]; then
               	apply_backport_patches
                BACKPORT_INCLUDES='-I${CWD}/kernel_addons/backport/'${BACKPORT_DIR}/include/
        fi
}

parseparams() {

	while [ ! -z "$1" ]
	do
		case $1 in
			--with-memtrack)
				CONFIG_MEMTRACK="m"
			;;
		esac

		shift
	done
}

main() {

#Set default values
KVERSION=${KVERSION:-$(uname -r)}
WITH_QUILT=${WITH_QUILT:-"yes"}
WITH_PATCH=${WITH_PATCH:-"yes"}
BACKPORT_INCLUDES=""
EXTRA_FLAGS=""
CONFIG_MEMTRACK=""

parseparams $@


WITH_BACKPORT_PATCHES=${WITH_BACKPORT_PATCHES:-"yes"}

QUILT=${QUILT:-$(/usr/bin/which quilt  2> /dev/null)}
CWD=$(pwd)
CONFIG="config.mk"
PATCH_DIR=${PATCH_DIR:-""}

        # Check parameters
        if [ "$WITH_PATCH" == "yes" ] && [ "$WITH_QUILT" == "yes" ] && [[ ! -x ${QUILT} || ! -n "${QUILT}" ]]; then
                echo "Quilt ${QUILT} does not exist... Going to use patch."
                WITH_QUILT="no"
        fi

        patches_handle

# Remove patches dir
/bin/rm -rf ${CWD}/kernel_patches

        # Create config.mk
        /bin/rm -f ${CWD}/${CONFIG}
        cat >> ${CWD}/${CONFIG} << EOFCONFIG
KVERSION=${KVERSION}
ARCH=`uname -m`
MODULES_DIR:=/lib/modules/${KVERSION}/updates
KSRC:=/lib/modules/${KVERSION}/build
CWD=${CWD}
BACKPORT_INCLUDES:=${BACKPORT_INCLUDES}
MLNX_EN_EXTRA_CFLAGS:=${EXTRA_FLAGS}
CONFIG_MEMTRACK:=${CONFIG_MEMTRACK}
EOFCONFIG
        
echo "Created ${CONFIG}:"
cat ${CWD}/${CONFIG}

# Create autoconf.h
#/bin/rm -f ${CWD}/include/linux/autoconf.h
mkdir -p ${CWD}/include/linux

cat >> ${CWD}/include/linux/autoconf.h << EOFAUTO
#define CONFIG_MLX4_CORE 1
#define CONFIG_MLX4_EN 1
EOFAUTO


}

main $@
