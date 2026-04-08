sudo find ~/ris602/autopwn -name "*.pyc" -delete
sudo find ~/ris602/autopwn -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null
