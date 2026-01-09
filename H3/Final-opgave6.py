numbers = [4, 7, 2, 9, 5, 12, 15]

numbers2 = [num for num in numbers if num > 5]
print(numbers2)

average = sum(numbers2) / len(numbers2) if numbers2 else 0
print("the avarge numbers value is:", average)