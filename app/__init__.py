from flask import Flask
from main.config import Config
app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello World!'

isDebugMode = Config.DEBUG == 'true' if True else False
if __name__ == '__main__':
    app.run(isDebugMode, port=Config.PORT)
