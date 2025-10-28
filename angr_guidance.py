# Angr Symbolic Execution Guidance
# Generated from App-Level CFG Analysis

## Composite Path 1
# Entry: onClick
# Summary: Entry: onClick -> handleAdmin -> parseIntInput (8 blocks)
path_1 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 2,
            'path_summary': 'onClick: block_0 -> block_1 (2 blocks)'
        },
        {
            'method': 'handleAdmin',
            'blocks': 2,
            'path_summary': 'handleAdmin: block_0 -> block_1 (2 blocks)'
        },
        {
            'method': 'parseIntInput',
            'blocks': 4,
            'path_summary': 'parseIntInput: block_0 -> block_3 (4 blocks)'
        },
    ]
}

## Composite Path 2
# Entry: onClick
# Summary: Entry: onClick -> handleAdmin -> parseIntInput (8 blocks)
path_2 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 2,
            'path_summary': 'onClick: block_0 -> block_1 (2 blocks)'
        },
        {
            'method': 'handleAdmin',
            'blocks': 2,
            'path_summary': 'handleAdmin: block_0 -> block_1 (2 blocks)'
        },
        {
            'method': 'parseIntInput',
            'blocks': 4,
            'path_summary': 'parseIntInput: block_0 -> block_4 (4 blocks)'
        },
    ]
}

## Composite Path 3
# Entry: onClick
# Summary: Entry: onClick -> handleAdmin -> parseIntInput (7 blocks)
path_3 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 2,
            'path_summary': 'onClick: block_0 -> block_1 (2 blocks)'
        },
        {
            'method': 'handleAdmin',
            'blocks': 2,
            'path_summary': 'handleAdmin: block_0 -> block_1 (2 blocks)'
        },
        {
            'method': 'parseIntInput',
            'blocks': 3,
            'path_summary': 'parseIntInput: block_0 -> block_4 (3 blocks)'
        },
    ]
}

## Composite Path 4
# Entry: onClick
# Summary: Entry: onClick -> handleAdmin -> parseIntInput (6 blocks)
path_4 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 2,
            'path_summary': 'onClick: block_0 -> block_1 (2 blocks)'
        },
        {
            'method': 'handleAdmin',
            'blocks': 2,
            'path_summary': 'handleAdmin: block_0 -> block_1 (2 blocks)'
        },
        {
            'method': 'parseIntInput',
            'blocks': 2,
            'path_summary': 'parseIntInput: block_0 -> block_4 (2 blocks)'
        },
    ]
}

## Composite Path 5
# Entry: onClick
# Summary: Entry: onClick -> handleAdmin -> parseIntInput (8 blocks)
path_5 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 2,
            'path_summary': 'onClick: block_0 -> block_1 (2 blocks)'
        },
        {
            'method': 'handleAdmin',
            'blocks': 2,
            'path_summary': 'handleAdmin: block_0 -> block_2 (2 blocks)'
        },
        {
            'method': 'parseIntInput',
            'blocks': 4,
            'path_summary': 'parseIntInput: block_0 -> block_3 (4 blocks)'
        },
    ]
}

## Composite Path 6
# Entry: onClick
# Summary: Entry: onClick -> handleAdmin -> parseIntInput (8 blocks)
path_6 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 2,
            'path_summary': 'onClick: block_0 -> block_1 (2 blocks)'
        },
        {
            'method': 'handleAdmin',
            'blocks': 2,
            'path_summary': 'handleAdmin: block_0 -> block_2 (2 blocks)'
        },
        {
            'method': 'parseIntInput',
            'blocks': 4,
            'path_summary': 'parseIntInput: block_0 -> block_4 (4 blocks)'
        },
    ]
}

## Composite Path 7
# Entry: onClick
# Summary: Entry: onClick -> handleAdmin -> parseIntInput (7 blocks)
path_7 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 2,
            'path_summary': 'onClick: block_0 -> block_1 (2 blocks)'
        },
        {
            'method': 'handleAdmin',
            'blocks': 2,
            'path_summary': 'handleAdmin: block_0 -> block_2 (2 blocks)'
        },
        {
            'method': 'parseIntInput',
            'blocks': 3,
            'path_summary': 'parseIntInput: block_0 -> block_4 (3 blocks)'
        },
    ]
}

## Composite Path 8
# Entry: onClick
# Summary: Entry: onClick -> handleAdmin -> parseIntInput (6 blocks)
path_8 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 2,
            'path_summary': 'onClick: block_0 -> block_1 (2 blocks)'
        },
        {
            'method': 'handleAdmin',
            'blocks': 2,
            'path_summary': 'handleAdmin: block_0 -> block_2 (2 blocks)'
        },
        {
            'method': 'parseIntInput',
            'blocks': 2,
            'path_summary': 'parseIntInput: block_0 -> block_4 (2 blocks)'
        },
    ]
}

## Composite Path 9
# Entry: onClick
# Summary: Entry: onClick -> handleStudent -> parseIntInput (9 blocks)
path_9 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 3,
            'path_summary': 'onClick: block_0 -> block_3 (3 blocks)'
        },
        {
            'method': 'handleStudent',
            'blocks': 2,
            'path_summary': 'handleStudent: block_0 -> block_1 (2 blocks)'
        },
        {
            'method': 'parseIntInput',
            'blocks': 4,
            'path_summary': 'parseIntInput: block_0 -> block_3 (4 blocks)'
        },
    ]
}

## Composite Path 10
# Entry: onClick
# Summary: Entry: onClick -> handleStudent -> parseIntInput (9 blocks)
path_10 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 3,
            'path_summary': 'onClick: block_0 -> block_3 (3 blocks)'
        },
        {
            'method': 'handleStudent',
            'blocks': 2,
            'path_summary': 'handleStudent: block_0 -> block_1 (2 blocks)'
        },
        {
            'method': 'parseIntInput',
            'blocks': 4,
            'path_summary': 'parseIntInput: block_0 -> block_4 (4 blocks)'
        },
    ]
}

## Composite Path 11
# Entry: onClick
# Summary: Entry: onClick -> handleStudent -> parseIntInput (8 blocks)
path_11 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 3,
            'path_summary': 'onClick: block_0 -> block_3 (3 blocks)'
        },
        {
            'method': 'handleStudent',
            'blocks': 2,
            'path_summary': 'handleStudent: block_0 -> block_1 (2 blocks)'
        },
        {
            'method': 'parseIntInput',
            'blocks': 3,
            'path_summary': 'parseIntInput: block_0 -> block_4 (3 blocks)'
        },
    ]
}

## Composite Path 12
# Entry: onClick
# Summary: Entry: onClick -> handleStudent -> parseIntInput (7 blocks)
path_12 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 3,
            'path_summary': 'onClick: block_0 -> block_3 (3 blocks)'
        },
        {
            'method': 'handleStudent',
            'blocks': 2,
            'path_summary': 'handleStudent: block_0 -> block_1 (2 blocks)'
        },
        {
            'method': 'parseIntInput',
            'blocks': 2,
            'path_summary': 'parseIntInput: block_0 -> block_4 (2 blocks)'
        },
    ]
}

## Composite Path 13
# Entry: onClick
# Summary: Entry: onClick -> handleStudent -> parseIntInput (9 blocks)
path_13 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 3,
            'path_summary': 'onClick: block_0 -> block_3 (3 blocks)'
        },
        {
            'method': 'handleStudent',
            'blocks': 2,
            'path_summary': 'handleStudent: block_0 -> block_2 (2 blocks)'
        },
        {
            'method': 'parseIntInput',
            'blocks': 4,
            'path_summary': 'parseIntInput: block_0 -> block_3 (4 blocks)'
        },
    ]
}

## Composite Path 14
# Entry: onClick
# Summary: Entry: onClick -> handleStudent -> parseIntInput (9 blocks)
path_14 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 3,
            'path_summary': 'onClick: block_0 -> block_3 (3 blocks)'
        },
        {
            'method': 'handleStudent',
            'blocks': 2,
            'path_summary': 'handleStudent: block_0 -> block_2 (2 blocks)'
        },
        {
            'method': 'parseIntInput',
            'blocks': 4,
            'path_summary': 'parseIntInput: block_0 -> block_4 (4 blocks)'
        },
    ]
}

## Composite Path 15
# Entry: onClick
# Summary: Entry: onClick -> handleStudent -> parseIntInput (8 blocks)
path_15 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 3,
            'path_summary': 'onClick: block_0 -> block_3 (3 blocks)'
        },
        {
            'method': 'handleStudent',
            'blocks': 2,
            'path_summary': 'handleStudent: block_0 -> block_2 (2 blocks)'
        },
        {
            'method': 'parseIntInput',
            'blocks': 3,
            'path_summary': 'parseIntInput: block_0 -> block_4 (3 blocks)'
        },
    ]
}

## Composite Path 16
# Entry: onClick
# Summary: Entry: onClick -> handleStudent -> parseIntInput (7 blocks)
path_16 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 3,
            'path_summary': 'onClick: block_0 -> block_3 (3 blocks)'
        },
        {
            'method': 'handleStudent',
            'blocks': 2,
            'path_summary': 'handleStudent: block_0 -> block_2 (2 blocks)'
        },
        {
            'method': 'parseIntInput',
            'blocks': 2,
            'path_summary': 'parseIntInput: block_0 -> block_4 (2 blocks)'
        },
    ]
}

## Composite Path 17
# Entry: onClick
# Summary: Entry: onClick -> handleGuest -> parseBooleanInput (14 blocks)
path_17 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 5,
            'path_summary': 'onClick: block_0 -> block_6 (5 blocks)'
        },
        {
            'method': 'handleGuest',
            'blocks': 2,
            'path_summary': 'handleGuest: block_0 -> block_1 (2 blocks)'
        },
        {
            'method': 'parseBooleanInput',
            'blocks': 7,
            'path_summary': 'parseBooleanInput: block_0 -> block_6 (7 blocks)'
        },
    ]
}

## Composite Path 18
# Entry: onClick
# Summary: Entry: onClick -> handleGuest -> parseBooleanInput (14 blocks)
path_18 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 5,
            'path_summary': 'onClick: block_0 -> block_6 (5 blocks)'
        },
        {
            'method': 'handleGuest',
            'blocks': 2,
            'path_summary': 'handleGuest: block_0 -> block_1 (2 blocks)'
        },
        {
            'method': 'parseBooleanInput',
            'blocks': 7,
            'path_summary': 'parseBooleanInput: block_0 -> block_7 (7 blocks)'
        },
    ]
}

## Composite Path 19
# Entry: onClick
# Summary: Entry: onClick -> handleGuest -> parseBooleanInput (13 blocks)
path_19 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 5,
            'path_summary': 'onClick: block_0 -> block_6 (5 blocks)'
        },
        {
            'method': 'handleGuest',
            'blocks': 2,
            'path_summary': 'handleGuest: block_0 -> block_1 (2 blocks)'
        },
        {
            'method': 'parseBooleanInput',
            'blocks': 6,
            'path_summary': 'parseBooleanInput: block_0 -> block_7 (6 blocks)'
        },
    ]
}

## Composite Path 20
# Entry: onClick
# Summary: Entry: onClick -> handleGuest -> parseBooleanInput (12 blocks)
path_20 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 5,
            'path_summary': 'onClick: block_0 -> block_6 (5 blocks)'
        },
        {
            'method': 'handleGuest',
            'blocks': 2,
            'path_summary': 'handleGuest: block_0 -> block_1 (2 blocks)'
        },
        {
            'method': 'parseBooleanInput',
            'blocks': 5,
            'path_summary': 'parseBooleanInput: block_0 -> block_7 (5 blocks)'
        },
    ]
}

## Composite Path 21
# Entry: onClick
# Summary: Entry: onClick -> handleGuest -> parseBooleanInput (11 blocks)
path_21 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 5,
            'path_summary': 'onClick: block_0 -> block_6 (5 blocks)'
        },
        {
            'method': 'handleGuest',
            'blocks': 2,
            'path_summary': 'handleGuest: block_0 -> block_1 (2 blocks)'
        },
        {
            'method': 'parseBooleanInput',
            'blocks': 4,
            'path_summary': 'parseBooleanInput: block_0 -> block_8 (4 blocks)'
        },
    ]
}

## Composite Path 22
# Entry: onClick
# Summary: Entry: onClick -> handleGuest -> parseBooleanInput (10 blocks)
path_22 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 5,
            'path_summary': 'onClick: block_0 -> block_6 (5 blocks)'
        },
        {
            'method': 'handleGuest',
            'blocks': 2,
            'path_summary': 'handleGuest: block_0 -> block_1 (2 blocks)'
        },
        {
            'method': 'parseBooleanInput',
            'blocks': 3,
            'path_summary': 'parseBooleanInput: block_0 -> block_8 (3 blocks)'
        },
    ]
}

## Composite Path 23
# Entry: onClick
# Summary: Entry: onClick -> handleGuest -> parseBooleanInput (9 blocks)
path_23 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 5,
            'path_summary': 'onClick: block_0 -> block_6 (5 blocks)'
        },
        {
            'method': 'handleGuest',
            'blocks': 2,
            'path_summary': 'handleGuest: block_0 -> block_1 (2 blocks)'
        },
        {
            'method': 'parseBooleanInput',
            'blocks': 2,
            'path_summary': 'parseBooleanInput: block_0 -> block_8 (2 blocks)'
        },
    ]
}

## Composite Path 24
# Entry: onClick
# Summary: Entry: onClick -> handleGuest -> parseBooleanInput (14 blocks)
path_24 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 5,
            'path_summary': 'onClick: block_0 -> block_6 (5 blocks)'
        },
        {
            'method': 'handleGuest',
            'blocks': 2,
            'path_summary': 'handleGuest: block_0 -> block_2 (2 blocks)'
        },
        {
            'method': 'parseBooleanInput',
            'blocks': 7,
            'path_summary': 'parseBooleanInput: block_0 -> block_6 (7 blocks)'
        },
    ]
}

## Composite Path 25
# Entry: onClick
# Summary: Entry: onClick -> handleGuest -> parseBooleanInput (14 blocks)
path_25 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 5,
            'path_summary': 'onClick: block_0 -> block_6 (5 blocks)'
        },
        {
            'method': 'handleGuest',
            'blocks': 2,
            'path_summary': 'handleGuest: block_0 -> block_2 (2 blocks)'
        },
        {
            'method': 'parseBooleanInput',
            'blocks': 7,
            'path_summary': 'parseBooleanInput: block_0 -> block_7 (7 blocks)'
        },
    ]
}

## Composite Path 26
# Entry: onClick
# Summary: Entry: onClick -> handleGuest -> parseBooleanInput (13 blocks)
path_26 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 5,
            'path_summary': 'onClick: block_0 -> block_6 (5 blocks)'
        },
        {
            'method': 'handleGuest',
            'blocks': 2,
            'path_summary': 'handleGuest: block_0 -> block_2 (2 blocks)'
        },
        {
            'method': 'parseBooleanInput',
            'blocks': 6,
            'path_summary': 'parseBooleanInput: block_0 -> block_7 (6 blocks)'
        },
    ]
}

## Composite Path 27
# Entry: onClick
# Summary: Entry: onClick -> handleGuest -> parseBooleanInput (12 blocks)
path_27 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 5,
            'path_summary': 'onClick: block_0 -> block_6 (5 blocks)'
        },
        {
            'method': 'handleGuest',
            'blocks': 2,
            'path_summary': 'handleGuest: block_0 -> block_2 (2 blocks)'
        },
        {
            'method': 'parseBooleanInput',
            'blocks': 5,
            'path_summary': 'parseBooleanInput: block_0 -> block_7 (5 blocks)'
        },
    ]
}

## Composite Path 28
# Entry: onClick
# Summary: Entry: onClick -> handleGuest -> parseBooleanInput (11 blocks)
path_28 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 5,
            'path_summary': 'onClick: block_0 -> block_6 (5 blocks)'
        },
        {
            'method': 'handleGuest',
            'blocks': 2,
            'path_summary': 'handleGuest: block_0 -> block_2 (2 blocks)'
        },
        {
            'method': 'parseBooleanInput',
            'blocks': 4,
            'path_summary': 'parseBooleanInput: block_0 -> block_8 (4 blocks)'
        },
    ]
}

## Composite Path 29
# Entry: onClick
# Summary: Entry: onClick -> handleGuest -> parseBooleanInput (10 blocks)
path_29 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 5,
            'path_summary': 'onClick: block_0 -> block_6 (5 blocks)'
        },
        {
            'method': 'handleGuest',
            'blocks': 2,
            'path_summary': 'handleGuest: block_0 -> block_2 (2 blocks)'
        },
        {
            'method': 'parseBooleanInput',
            'blocks': 3,
            'path_summary': 'parseBooleanInput: block_0 -> block_8 (3 blocks)'
        },
    ]
}

## Composite Path 30
# Entry: onClick
# Summary: Entry: onClick -> handleGuest -> parseBooleanInput (9 blocks)
path_30 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 5,
            'path_summary': 'onClick: block_0 -> block_6 (5 blocks)'
        },
        {
            'method': 'handleGuest',
            'blocks': 2,
            'path_summary': 'handleGuest: block_0 -> block_2 (2 blocks)'
        },
        {
            'method': 'parseBooleanInput',
            'blocks': 2,
            'path_summary': 'parseBooleanInput: block_0 -> block_8 (2 blocks)'
        },
    ]
}

## Composite Path 31
# Entry: onClick
# Summary: Entry: onClick (4 blocks)
path_31 = {
    'entry_point': 'onClick',
    'method_executions': [
        {
            'method': 'onClick',
            'blocks': 4,
            'path_summary': 'onClick: block_0 -> block_6 (4 blocks)'
        },
    ]
}

