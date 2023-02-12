#Password Generator Project
def generate_password(nr_letters,nr_symbols,nr_numbers):
  import random
  letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
  numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
  symbols = ['!', '#', '$', '%', '&', '(', ')', '*', '+']



  #Eazy Level - Order not randomised:
  #e.g. 4 letter, 2 symbol, 2 number = JduE&!91
  password_ord = ''
  password = ""

  for i in range(1, (nr_letters + 1)):
    password_ord += letters[random.randint(0, len(letters) - 1)]
  for i in range(1, (nr_symbols + 1)):
    password_ord += symbols[random.randint(0, len(symbols) - 1)]
  for i in range(1, (nr_numbers + 1)):
    password_ord += numbers[random.randint(0, len(numbers) - 1)]
  password_list = list(password_ord)
  random.shuffle(password_list)
  for ch in password_list:
    password += ch
  return password














#Hard Level - Order of characters randomised:
#e.g. 4 letter, 2 symbol, 2 number = g^2jk8&P
