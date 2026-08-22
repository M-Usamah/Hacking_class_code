import subprocess
import optparse


parser = optparse.OptionParser()

parser.add_option('-i','--interface',dest='interface',help='Enter Network Abopter')
parser.add_option('-m','--mac', dest="new_mac",help="Enter New Mac Address")
parser.add_option('-n', "--name", dest="name",help="Enter your Name")

(option, arguments) = parser.parse_args()

print(option)
print(arguments)

interface = option.interface
new_mac = option.new_mac

# interface = input("Enter the Interface: ")
# new_mac = input("Enter New Mac Address: ")


try:
    subprocess.run(["sudo","ifconfig",interface],check=True)
    subprocess.run(['sudo','ifconfig',interface,'down'],check=True)
    subprocess.run(['sudo','ifconfig',interface,'hw','ether',new_mac],check=True)
    subprocess.run(['sudo','ifconfig',interface,'up'],check=True)
    subprocess.run(["sudo","ifconfig",interface],check=True) 
except:
    print("Something gone wrong")

