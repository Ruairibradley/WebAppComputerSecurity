from app import create_app, bootstrap

# entry point (terminal)
app = create_app()

if __name__ == "__main__":
    bootstrap(app)          # create DB, seed admin on first run
    app.run(debug=True)    