str1 = "James"
print("Original String is:", str1)

#Get the first character
first_char = str1[0]

#Get the middle character
middle_index = len(str1) // 2
middle_char = str1[middle_index]

#Get the last character
last_char = str1[-1]

#Combine them to form the new string
new_string = first_char + middle_char + last_char

print("New String:", new_string)



str2 = "James"
print("Original String is", str2)

# Get first, middle, and last characters
Result = str2[0] + str2[len(str2)//2] + str2[-1]

print("New String:", Result)
