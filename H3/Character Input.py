name = input ("what is your name?")
print ("hello " + name)
birthdate = input ("what year were you born?")
print ("you are " + birthdate + " years old")

def age_xyear ():
    
    while True:
    
        age_request = input ("in how many years do you want to know your age?")
    
        try:

            if int(age_request) < 0:
                print ("please enter a positive number")
                continue

            elif int (age_request) >= 0:
                future_age = int(age_request) - int(birthdate)
                print ("in " + age_request + " years you will be " + str(future_age))
                break
        
        except ValueError:
            print ("please enter a valid number")

age_xyear()