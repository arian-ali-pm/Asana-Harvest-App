from asanaharvestdashboard import app
from a2wsgi import ASGIMiddleware

application = ASGIMiddleware(app)
