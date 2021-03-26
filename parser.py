import re

f = open("IOKitLib.h")
lines = [line for line in f.readlines()]
f.close()

re1 = re.compile('\\b[\\w ]*')
re2 = re.compile('\\w+\\(')
functions = []

for i in range(0,len(lines)-1):
	line = lines[i].split('//')[0]
	if (re1.match(line)):
		i+=1
		line2 = lines[i].split('//')[0]
		# if this matches, we actually have a
		# function signature in line and line2.
		if (re2.match(line2)):
			myfunc = '' + line[:-1] + ' ' + line2

			# take everything until function ends as well.
			while not (')' in myfunc):
				i+=1
				myfunc += lines[i].split('//')[0]

			functions.append(' '.join(myfunc.split()))

print(f"Found {len(functions)} functions!")
f = open("functions.txt", "w")
for func in functions:
	f.writelines(f"{func}\n")
f.close()
# for fn in functions:
# 	print(fn)