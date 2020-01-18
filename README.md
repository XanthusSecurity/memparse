# memparse
memParse is intended to recover clear text passwords from memory that have been sent via HTTPS POST login requests

Capture the POST request in your favourite proxy software, add a regex entry and you're off to the races!

Happy hunting!

ex.
<pre><code>MemProcInspector.AddRegex("GMail", "identifier=.{1,200}");</code></pre>
