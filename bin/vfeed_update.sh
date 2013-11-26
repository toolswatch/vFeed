# vfeed_update.sh - vFeed Update Wrapper
# Version: 0.2 (20131126)
# Created By: Glenn 'devalias' Grant (http://devalias.net)
# License: The MIT License (MIT) - Copyright (c) 2013 Glenn 'devalias' Grant (see http://choosealicense.com/licenses/mit/ for full license text)
# vFeed URL: https://github.com/toolswatch/vfeed

# cd "$(dirname "$0")/.."
cd ~/pentest/vFeed

# Update the vFeed installation from git
if [ -d ".git" ]; then
  echo "[vFeed::Git] .git found. Updating to latest version"
  git checkout master && git pull origin master
fi

# Update the vFeed database
echo "[vFeed::Update] Updating database"
python vfeed_update.py "$@"
