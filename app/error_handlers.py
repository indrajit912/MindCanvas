# Error Handlers for the site
#
# Author: Indrajit Ghosh
# Created On: Mar 24, 2024
#

from flask import render_template


##########################################
#        Page not found!
##########################################
def page_not_found(error):
    return render_template('errors/404.html'), 404


##########################################
#        Internal Server Error!
##########################################
def internal_server_error(error):
    return render_template('errors/500.html', error=error), 500

