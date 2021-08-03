CONFIG = {
    "folder_analysis": {
        "exclude_filenames": {
            r"^\..*",
            r"^__.*",
            r"LICENSE.md",
        },
        "exclude_paths": {r"imgs"},
    },
    "readme": {
        "mandatory_headings": {"Purpose", "Project Description"},
        "mandatory_sections": {"License"},
        "unnumbered_heading": {
            "Purpose",
            "Project Description",
            "Table of Contents",
        },
        # Text line to force a exact match in final readme
        # Add line no (from template) to the mandatory_lines
        # use int or string as L3-4
        "mandatory_lines": [
            3,
            4,
        ],
        # Text line to ignore
        # Add line no (from template) here to suppress the warning
        # use int or string as L3-4
        "ignore_lines": [
            "L6-8",
            "L27-41",
            "L143-204",
            "L219-220",
            "L225-227",
        ],
    },
    "commented_code": {
        # Lines does not count as commendted code
        "special_lines": {"# -*- coding: utf-8 -*-"}
    },
}
