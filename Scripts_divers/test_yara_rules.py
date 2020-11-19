import os
import yara
import sys
pfile={}
stra=False
if len(sys.argv) == 3:
    stra = True
if os.path.isfile(sys.argv[1]):
    pfile[str(os.path.basename(sys.argv[1]))] = str(sys.argv[1])
rules = yara.compile(filepaths=pfile, externals={})
for root, directories, filenames in os.walk(sys.argv[2]):
    for filename in filenames:
        try:
            ret_yara = rules.match(os.path.join(root, filename), externals={}, timeout=120)
        except:
            continue
        for match in ret_yara:
            r=[]
            s=[]
            for st in match.strings:
                if not st[1] in r:
                    r.append(st[1])
                if stra and not st[2] in s:
                    r.append(st[2])
            print('YARA on '+os.path.basename(filename)+' with rules: '+match.rule+' match DEBUG:'+str(r) + 'Str finded:' + str(s))
