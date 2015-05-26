input_file = open("api_blueprint.py", 'r')
output_file = open("cli_scripts.txt", 'w')

lines = input_file.readlines()

for line in lines:
    if "@blueprint.route" not in line:
        continue
    else:
        output_file.write(line)





'''
for line in lines:
    index = line.find("@blueprint.route('/api")
    if index == -1:
        continue
    else:
        print line
        output_file.write(line)
'''
