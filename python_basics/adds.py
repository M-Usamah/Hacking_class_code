import optparse

parser = optparse.OptionParser()

parser.add_option('-a', "--num1", dest="num1", help="Enter a Number")
parser.add_option('-b', "--num2", dest='num2', help="Enter a Number")

(option, args)=parser.parse_args()


print(option, args) 
# print(option.num1)
# print(option.num2)

# print(option.num1+option.num2)