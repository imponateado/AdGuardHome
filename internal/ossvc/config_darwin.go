//go:build darwin

package ossvc

import (
	"github.com/kardianos/service"
)

// configureServiceOptions defines additional settings of the service
// configuration on macOS.  conf must not be nil.
func configureOSOptions(conf *service.Config) {
	conf.Option["LaunchdConfig"] = launchdConfig
}

// launchdConfig is the template for Launchd service file.  Basically the same
// template as the one defined in github.com/kardianos/service but with two
// additional keys:
//   - StandardOutPath
//   - StandardErrorPath
const launchdConfig = `<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd" >
<plist version='1.0'>
<dict>
<key>Label</key><string>{{Name | html}}</string>
<key>ProgramArguments</key>
<array>
        <string>{{Path | html}}</string>
{{range Arguments}}
        <string>{{. | html}}</string>
{{end}}
</array>
{{if UserName}}<key>UserName</key><string>{{UserName | html}}</string>{{end}}
{{if ChRoot}}<key>RootDirectory</key><string>{{ChRoot | html}}</string>{{end}}
{{if WorkingDirectory}}<key>WorkingDirectory</key><string>{{WorkingDirectory | html}}</string>{{end}}
<key>SessionCreate</key><{{SessionCreate}}/>
<key>KeepAlive</key><{{KeepAlive}}/>
<key>RunAtLoad</key><{{RunAtLoad}}/>
<key>Disabled</key><false/>
<key>StandardOutPath</key>
<string>` + launchdStdoutPath + `</string>
<key>StandardErrorPath</key>
<string>` + launchdStderrPath + `</string>
</dict>
</plist>
`
