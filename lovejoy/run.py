from app import create_app, bootstrap

# entry 
app = create_app()

if __name__ == "__main__":
    """
    Run the Flask application."""
    bootstrap(app)          # create DB / seed admin on first run
    app.run(debug=True)    