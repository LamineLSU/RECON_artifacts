# Angr Symbolic Execution Guidance
# Generated from App-Level CFG Analysis

## Composite Path 1
# Entry: -$$Nest$fputselectedPath
# Summary: Entry: -$$Nest$fputselectedPath (1 blocks)
path_1 = {
    'entry_point': '-$$Nest$fputselectedPath',
    'method_executions': [
        {
            'method': '-$$Nest$fputselectedPath',
            'blocks': 1,
            'path_summary': '-$$Nest$fputselectedPath: block_0 -> block_0 (1 blocks)'
        },
    ]
}

## Composite Path 2
# Entry: -$$Nest$mexecuteSubPath
# Summary: Entry: -$$Nest$mexecuteSubPath -> executeSubPath (3 blocks)
path_2 = {
    'entry_point': '-$$Nest$mexecuteSubPath',
    'method_executions': [
        {
            'method': '-$$Nest$mexecuteSubPath',
            'blocks': 1,
            'path_summary': '-$$Nest$mexecuteSubPath: block_0 -> block_0 (1 blocks)'
        },
        {
            'method': 'executeSubPath',
            'blocks': 2,
            'path_summary': 'executeSubPath: block_0 -> block_1 (2 blocks)'
        },
    ]
}

## Composite Path 3
# Entry: -$$Nest$mexecuteSubPath
# Summary: Entry: -$$Nest$mexecuteSubPath -> executeSubPath -> <init> (5 blocks)
path_3 = {
    'entry_point': '-$$Nest$mexecuteSubPath',
    'method_executions': [
        {
            'method': '-$$Nest$mexecuteSubPath',
            'blocks': 1,
            'path_summary': '-$$Nest$mexecuteSubPath: block_0 -> block_0 (1 blocks)'
        },
        {
            'method': 'executeSubPath',
            'blocks': 3,
            'path_summary': 'executeSubPath: block_0 -> block_3 (3 blocks)'
        },
        {
            'method': '<init>',
            'blocks': 1,
            'path_summary': '<init>: block_0 -> block_0 (1 blocks)'
        },
    ]
}

## Composite Path 4
# Entry: -$$Nest$mexecuteSubPath
# Summary: Entry: -$$Nest$mexecuteSubPath -> executeSubPath -> <init> (5 blocks)
path_4 = {
    'entry_point': '-$$Nest$mexecuteSubPath',
    'method_executions': [
        {
            'method': '-$$Nest$mexecuteSubPath',
            'blocks': 1,
            'path_summary': '-$$Nest$mexecuteSubPath: block_0 -> block_0 (1 blocks)'
        },
        {
            'method': 'executeSubPath',
            'blocks': 3,
            'path_summary': 'executeSubPath: block_0 -> block_4 (3 blocks)'
        },
        {
            'method': '<init>',
            'blocks': 1,
            'path_summary': '<init>: block_0 -> block_0 (1 blocks)'
        },
    ]
}

## Composite Path 5
# Entry: -$$Nest$mexecuteSubPath
# Summary: Entry: -$$Nest$mexecuteSubPath -> executeSubPath -> <init> (5 blocks)
path_5 = {
    'entry_point': '-$$Nest$mexecuteSubPath',
    'method_executions': [
        {
            'method': '-$$Nest$mexecuteSubPath',
            'blocks': 1,
            'path_summary': '-$$Nest$mexecuteSubPath: block_0 -> block_0 (1 blocks)'
        },
        {
            'method': 'executeSubPath',
            'blocks': 3,
            'path_summary': 'executeSubPath: block_0 -> block_6 (3 blocks)'
        },
        {
            'method': '<init>',
            'blocks': 1,
            'path_summary': '<init>: block_0 -> block_0 (1 blocks)'
        },
    ]
}

## Composite Path 6
# Entry: -$$Nest$mexecuteSubPath
# Summary: Entry: -$$Nest$mexecuteSubPath -> executeSubPath -> <init> (5 blocks)
path_6 = {
    'entry_point': '-$$Nest$mexecuteSubPath',
    'method_executions': [
        {
            'method': '-$$Nest$mexecuteSubPath',
            'blocks': 1,
            'path_summary': '-$$Nest$mexecuteSubPath: block_0 -> block_0 (1 blocks)'
        },
        {
            'method': 'executeSubPath',
            'blocks': 3,
            'path_summary': 'executeSubPath: block_0 -> block_7 (3 blocks)'
        },
        {
            'method': '<init>',
            'blocks': 1,
            'path_summary': '<init>: block_0 -> block_0 (1 blocks)'
        },
    ]
}

## Composite Path 7
# Entry: -$$Nest$mexecuteSubPath
# Summary: Entry: -$$Nest$mexecuteSubPath -> executeSubPath -> <init> (5 blocks)
path_7 = {
    'entry_point': '-$$Nest$mexecuteSubPath',
    'method_executions': [
        {
            'method': '-$$Nest$mexecuteSubPath',
            'blocks': 1,
            'path_summary': '-$$Nest$mexecuteSubPath: block_0 -> block_0 (1 blocks)'
        },
        {
            'method': 'executeSubPath',
            'blocks': 3,
            'path_summary': 'executeSubPath: block_0 -> block_9 (3 blocks)'
        },
        {
            'method': '<init>',
            'blocks': 1,
            'path_summary': '<init>: block_0 -> block_0 (1 blocks)'
        },
    ]
}

## Composite Path 8
# Entry: -$$Nest$mexecuteSubPath
# Summary: Entry: -$$Nest$mexecuteSubPath -> executeSubPath -> <init> (5 blocks)
path_8 = {
    'entry_point': '-$$Nest$mexecuteSubPath',
    'method_executions': [
        {
            'method': '-$$Nest$mexecuteSubPath',
            'blocks': 1,
            'path_summary': '-$$Nest$mexecuteSubPath: block_0 -> block_0 (1 blocks)'
        },
        {
            'method': 'executeSubPath',
            'blocks': 3,
            'path_summary': 'executeSubPath: block_0 -> block_10 (3 blocks)'
        },
        {
            'method': '<init>',
            'blocks': 1,
            'path_summary': '<init>: block_0 -> block_0 (1 blocks)'
        },
    ]
}

## Composite Path 9
# Entry: -$$Nest$mshowSubChoiceLayout
# Summary: Entry: -$$Nest$mshowSubChoiceLayout -> showSubChoiceLayout (2 blocks)
path_9 = {
    'entry_point': '-$$Nest$mshowSubChoiceLayout',
    'method_executions': [
        {
            'method': '-$$Nest$mshowSubChoiceLayout',
            'blocks': 1,
            'path_summary': '-$$Nest$mshowSubChoiceLayout: block_0 -> block_0 (1 blocks)'
        },
        {
            'method': 'showSubChoiceLayout',
            'blocks': 1,
            'path_summary': 'showSubChoiceLayout: block_0 -> block_0 (1 blocks)'
        },
    ]
}

