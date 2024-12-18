import cli.main
import web.server

cli.main.painting()
web.server.app.run(host='0.0.0.0', port=7100)
