# Tips for lab1

## 运行指令

`
python autograder_lab1_client.py 20194.0.0.19000 6 milestone1 submit
`

如何测试lab1代码：
要修改的文件是位于老师环境下的home文件夹下的.playground/connector/poop 的protocol.py
测试echotest的方法，到home底下的lab1文件夹下，server端：python echotest.py server -stack=poop
client端：python echotest.py localhost 101 -stack=poop
raw_echotest测试方法： server端： python raw_echotest.py server --stack poop
client端： python raw_echotest.py localhost --port 202 --count 10000 --stack poop