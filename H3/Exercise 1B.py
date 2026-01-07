str3 = "JohnDipPeta"
str4 = "JaSonAy"

print("Original Strings are:", str3, str4)

#Get the first character
middle_index1 = len(str3) // 2 - 1
middle_char1 = str3[middle_index1]

#Get the middle character
middle_index2 = len(str3) // 2
middle_char2 = str3[middle_index2]

#Get the last character
middle_index3 = len(str3) // 2 + 1
middle_char3 = str3[middle_index3]

#Combines them 
new_string1 = middle_char1 + middle_char2 + middle_char3

print("New String:", new_string1)


#Get the first character
middle_index4 = len(str4) // 2 - 1
middle_char4 = str4[middle_index4]

#Get the middle character
middle_index5 = len(str4) // 2
middle_char5 = str4[middle_index5]

#Get the last character
middle_index6 = len(str4) // 2 + 1
middle_char6 = str4[middle_index6]

#Combines them 
new_string2 = middle_char4 + middle_char5 + middle_char6

print("New String:", new_string2)

#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

str1 = "JhonDipPeta"
str2 = "JaSonAy"

print("Original Strings are:", str1, str2)

result1 = str1[len(str1)//2 - 1] + str1[len(str1)//2] + str1[len(str1)//2 + 1]
# The frst part of the result1 gets the left middle character, the second part gets the middle character, and the third part gets the right middle character.

Result2 = str2[len(str2)//2 - 1] + str2[len(str2)//2] + str2[len(str2)//2 + 1]

print ("New Strings are:", result1, Result2)