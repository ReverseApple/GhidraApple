

# Objective-C Encoding Grammar

## For Methods...

```
Example: v24@0:8@16

v 24 @0 :8 @16
A B  C  D  E
```

A = Return Type \
B = Stack Frame Size \
C = First Argument (`self`) \
D = Second Argument (`SEL`, as indicated by `:`)


### Argument Structure:
`<type><stack_offset>`
