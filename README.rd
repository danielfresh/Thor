## Thor
Thor is an open source system to provides users a communication channel with the containers.
It can provide:
- An understanding of the real-time resource usage.
- A way to execute commands in the container.

## Install
```
#cd thor
#go build thor.go
#cd etc/tools
#./install
```
Thor will listen on port 9898. Then, to interact with the thor, you may make a tcp connection to this port.

## Request

```
type Request struct {
	// token
	Token      string `json:"token"`

	// time
	HeaderTime string `json:"time"`

	// type ("collector"/"executor")
	Type       string `json:"type"`

	// name (collector:"driect"/executor:"local")
	Name       string `json:"name"`

	// interval
	Interval   duration    `json:"interval"`

	// executions
	Executions int    `json:"executions"`

	// content
	Content    map[string]string `json:"content"`
}
```

## More
Yeah, for thor is not simple easy enough to use , we also provide a client of thor called "thorctl", you can use it to interact with the thor or learn the way from it.
