#!/bin/bash

#
# ndmtk - Network Discovery and Management Toolkit
# Copyright (C) 2016 Paul Greenberg @greenpau
#
# File: markdown.sh
#
# Purpose: This script converts documentation .rst files
# into .md format, inserts horizontal lines, and fixes
# headings.
#

cd "$(dirname "$0")"

for SECTION in reports userguide rules auth faqs index; do
    pandoc -f rst -t markdown -s ${SECTION}.rst -o ${SECTION}.tmp
    sed -i 's/.*Back to Top.*/:arrow_up: \[Back to top\]\(#top\)/' ${SECTION}.tmp
    sed -i '/^---$/{
        $!{ N
            N
            s/---\n\(.*title:s*.*\)\n.../\1/
        }
    }' ${SECTION}.tmp

    sed -i '/^[A-Za-z]/{
        $!{ N
            s/^\(.*\)\n=\+$/heading2: \1/
        }
    }' ${SECTION}.tmp

    sed -i '/^[A-Za-z]/{
        $!{ N
            s/^\(.*\)\n-\+$/heading3: \1/
        }
    }' ${SECTION}.tmp

    sed -i '/^:arrow/{
        $!{ N
            a *****\n
        }
    }' ${SECTION}.tmp

    sed -i 's/^title:\s*/# /;s/heading2:\s*/## /;s/heading3:\s*/### /;' ${SECTION}.tmp

    cat badges.md ${SECTION}.tmp > ${SECTION}.md
    echo "${SECTION}.md: ok"
done

rm *.tmp
