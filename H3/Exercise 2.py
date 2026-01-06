s1 = "Ault"
s2 = "kelly"

def String_merge(s1, s2):

# Get first half from s1 (Ault) (Au)
    firstpart = s1[:2]
# Define Second part from s2 (kelly)
    Secondpart = s2
#Gets last half from s1 (Ault) (lt)
    Thirdpart = s1[2:]

    return firstpart + Secondpart + Thirdpart

print(String_merge(s1, s2))

print (35*"-")#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

s3 = "Ault"
s4 = "kelly"

result = s3[:2] + s4 + s3[2:]

print (f"The original words was {s3} and {s4} after the merge it looks like this {result}")