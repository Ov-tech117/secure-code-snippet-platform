from flask import Flask, redirect, url_for, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from config import Config

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    db.init_app(app)
    
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)
    
    from models import User
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    from app.auth import auth_bp
    app.register_blueprint(auth_bp)
    
    from app.snippets import snippets_bp
    app.register_blueprint(snippets_bp)
    
    @app.route('/')
    def home():
        return render_template('home.html')
    
    @app.route('/dashboard')
    def dashboard():
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        from models import Snippet
        snippet_count = Snippet.query.filter_by(user_id=current_user.id).count()
        recent_snippets = Snippet.query.filter_by(user_id=current_user.id).order_by(Snippet.created_at.desc()).limit(5).all()
        return render_template('dashboard.html', snippet_count=snippet_count, recent_snippets=recent_snippets)
    
    return app