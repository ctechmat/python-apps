import os
import socket
import asyncio
import time
import random
import json
import subprocess
import yaml
from yaml import SafeLoader

from walkoff_app_sdk.app_base import AppBase

# Make file sample with namespace yara:
## curl http://localhost:5001/api/v1/files/create -H "Authorization: Bearer 09627dcb-7e2a-4843-819b-417d268ff840" -d '{"filename": "HelloWorld.yml", "org_id": "11f67b76-6051-4425-b0d6-be23daac6d12", "workflow_id": "global", "namespace": "sigma"}'

# 1. Generate the api.yaml based on downloaded files
# 2. Add a way to choose the rule and the target platform for it
# 3. Add the possibility of translating rules back and forth

# 4. Make it so you can start with Mitre Att&ck techniques 
# and automatically get the right rules set up with your tools :O
class Sigma(AppBase):
    __version__ = "1.1.0"
    app_name = "Sigma"  # this needs to match "name" in api.yaml

    def __init__(self, redis, logger, console_logger=None):
        """
        Each app should have this __init__ to set up Redis and logging.
        :param redis:
        :param logger:
        :param console_logger:
        """
        super().__init__(redis, logger, console_logger)
    
    def get_searches(self, backend, format, shuffle_category):
        files = self.get_file_namespace(shuffle_category)
        self.logger.info(f"Files: {files}")

        # This part should be in the SDK
        basedir = "rules"
        os.mkdir(basedir)
        for member in files.namelist():
            filename = os.path.basename(member)
            if not filename:
                continue

            self.logger.info("File: %s" % member)
            source = files.open(member)
            with open("%s/%s" % (basedir, source.name), "wb+") as tmp:
                filedata = source.read()
                self.logger.info("Filedata (%s): %s" % (source.name, filedata))
                tmp.write(filedata)
        
        self.logger.info(f"Dir: {os.listdir(basedir)}")

        rule = shuffle_category
        #filename = "file.yaml" 
        #with open(filename, "w+") as tmp:
        #    tmp.write(rule)
    
        code = "sigma convert --without-pipeline -t %s" % backend
        #if len(format) > 0:
        if format:
            if "list" in format:
                code += "--list"
            else:
                code += " -f %s" % format
    
        code += " rules/*" 
        self.logger.info("Code: %s"  %code)
        print(code)
        print()
        process = subprocess.Popen(
            code,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True,  # nosec
        )
        stdout = process.communicate()
        #self.logger.info("Stdout : %s" % stdout)
        item = ""
        if len(stdout[0]) > 0:
            print("Succesfully ran bash!")
            item = stdout[0]
            #self.logger.info("Item0 : %s" % item)
        else:
            print("FAILED to run bash: ", stdout[1])
            item = stdout[1]
    
        try:
            ret = item.decode("utf-8")
            #self.logger.info("Ret : %s" % ret)
            #ret = print("{rule: "+ item +"}")
            return ret
        except Exception:
            #json_item = '{"rule":"'+item+'"}'
            #json_convert = json.dumps(json_item, indent=3)
            #json_return = json.loads(json_convert)
            #return json_return
            return item
    
        #return '{rule: '+ item + '}'
        return item

if __name__ == "__main__":
    Sigma.run()
