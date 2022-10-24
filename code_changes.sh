if [[ `git status --porcelain` ]]; then
    # Changes
    echo "Code changes have been found on:"
    echo "`git status --porcelain`"
    echo "You must commit them before deployment steps."
    exit 1
else
    # No changes
    echo "No code changes found."
fi
