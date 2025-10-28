# Angr Symbolic Execution Guidance
# Generated from App-Level CFG Analysis

## Composite Path 1
# Entry: onClick
# Summary: Entry: onClick -> processStudents -> <init> (4 blocks)
path_1 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 2,
            'path_summary': 'onClick: block_0 -> block_1 (2 blocks)'
        },
        {
            'method': 'processStudents',
            'blocks': 1,
            'path_summary': 'processStudents: block_0 -> block_0 (1 blocks)'
        },
        {
            'method': '<init>',
            'blocks': 1,
            'path_summary': '<init>: block_0 -> block_0 (1 blocks)'
        },
    ]
}

## Composite Path 2
# Entry: onClick
# Summary: Entry: onClick -> processStaff -> <init> (5 blocks)
path_2 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 3,
            'path_summary': 'onClick: block_0 -> block_3 (3 blocks)'
        },
        {
            'method': 'processStaff',
            'blocks': 1,
            'path_summary': 'processStaff: block_0 -> block_0 (1 blocks)'
        },
        {
            'method': '<init>',
            'blocks': 1,
            'path_summary': '<init>: block_0 -> block_0 (1 blocks)'
        },
    ]
}

## Composite Path 3
# Entry: onClick
# Summary: Entry: onClick (5 blocks)
path_3 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 5,
            'path_summary': 'onClick: block_0 -> block_6 (5 blocks)'
        },
    ]
}

## Composite Path 4
# Entry: onClick
# Summary: Entry: onClick (4 blocks)
path_4 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 4,
            'path_summary': 'onClick: block_0 -> block_6 (4 blocks)'
        },
    ]
}

## Composite Path 5
# Entry: onCreate
# Summary: Entry: onCreate (1 blocks)
path_5 = {
    'entry_point': 'onCreate',
    'method_executions': [
        {
            'method': 'onCreate',
            'blocks': 1,
            'path_summary': 'onCreate: block_0 -> block_0 (1 blocks)'
        },
    ]
}

## Composite Path 6
# Entry: onClick
# Summary: Entry: onClick -> processCourse -> <init> (5 blocks)
path_6 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 3,
            'path_summary': 'onClick: block_0 -> block_2 (3 blocks)'
        },
        {
            'method': 'processCourse',
            'blocks': 1,
            'path_summary': 'processCourse: block_0 -> block_0 (1 blocks)'
        },
        {
            'method': '<init>',
            'blocks': 1,
            'path_summary': '<init>: block_0 -> block_0 (1 blocks)'
        },
    ]
}

## Composite Path 7
# Entry: onClick
# Summary: Entry: onClick (2 blocks)
path_7 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 2,
            'path_summary': 'onClick: block_0 -> block_2 (2 blocks)'
        },
    ]
}

