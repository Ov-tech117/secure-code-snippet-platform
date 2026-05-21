from flask import render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from app import db
from app.snippets import snippets_bp
from models import Snippet, AuditLog, Tag
from forms import SnippetForm
from app.security.analyzer import SecurityAnalyzer
import json

@snippets_bp.route('/new', methods=['GET', 'POST'])
@login_required
def new_snippet():
    form = SnippetForm()
    security_results = None
    
    if form.validate_on_submit():
        # Run security analysis
        analyzer = SecurityAnalyzer(form.code.data, form.language.data)
        security_results = analyzer.analyze()
        
        snippet = Snippet(
            title=form.title.data,
            code=form.code.data,
            language=form.language.data,
            user_id=current_user.id,
            security_score=security_results['score']
        )
        db.session.add(snippet)
        
        # Process tags
        if form.tags.data:
            tag_names = [t.strip().lower() for t in form.tags.data.split(',') if t.strip()]
            for tag_name in tag_names:
                tag = Tag.query.filter_by(name=tag_name).first()
                if not tag:
                    tag = Tag(name=tag_name)
                    db.session.add(tag)
                snippet.tags.append(tag)
        
        db.session.commit()
        
        log = AuditLog(
            user_id=current_user.id,
            action='create_snippet',
            snippet_id=snippet.id,
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
        # Show security warnings if any
        if security_results['has_issues']:
            flash(f'Snippet created with {len(security_results["issues"])} security issue(s)!', 'warning')
            for issue in security_results['issues']:
                flash(f'⚠️ {issue["type"]}: {issue["message"]}', 'danger')
        else:
            flash('Snippet created successfully! No security issues detected.', 'success')
        
        return redirect(url_for('snippets.view_snippet', snippet_id=snippet.id))
    
    return render_template('new_snippet.html', form=form, security_results=security_results)

@snippets_bp.route('/preview-security', methods=['POST'])
@login_required
def preview_security():
    data = json.loads(request.data)
    analyzer = SecurityAnalyzer(data.get('code', ''), data.get('language', 'python'))
    results = analyzer.analyze()
    return jsonify(results)

@snippets_bp.route('/view/<int:snippet_id>')
@login_required
def view_snippet(snippet_id):
    snippet = Snippet.query.get_or_404(snippet_id)
    
    # Run security analysis on the snippet code
    analyzer = SecurityAnalyzer(snippet.code, snippet.language)
    security_results = analyzer.analyze()
    
    return render_template('view_snippet.html', snippet=snippet, security_results=security_results)

@snippets_bp.route('/my-snippets')
@login_required
def my_snippets():
    snippets = Snippet.query.filter_by(user_id=current_user.id).order_by(Snippet.created_at.desc()).all()
    return render_template('my_snippets.html', snippets=snippets)

# DELETE ROUTE - ADD THIS
@snippets_bp.route('/delete/<int:snippet_id>')
@login_required
def delete_snippet(snippet_id):
    snippet = Snippet.query.get_or_404(snippet_id)
    
    # Check if user owns the snippet or is admin
    if snippet.user_id != current_user.id and current_user.role != 'admin':
        flash('You do not have permission to delete this snippet.', 'danger')
        return redirect(url_for('snippets.view_snippet', snippet_id=snippet.id))
    
    # Delete the snippet
    db.session.delete(snippet)
    db.session.commit()
    
    # Log the deletion
    log = AuditLog(
        user_id=current_user.id,
        action='delete_snippet',
        snippet_id=snippet.id,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    
    flash('Snippet deleted successfully!', 'success')
    return redirect(url_for('snippets.my_snippets'))