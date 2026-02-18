from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run()


# run.py
# from app import create_app
# from app.extensions import db

# app = create_app()

# # Add this before running
# with app.app_context():
#     db.create_all()
#     print("✅ Database initialized!")

# if __name__ == '__main__':
#     app.run(debug=True, host='0.0.0.0', port=5000)