from colors import Colors
import sys

def loading_bar(item_cur, items_total, clrs):
    percentage = (item_cur*100) / items_total
    bar = (percentage/5)*'=' + '>'
    if(clrs):
        sys.stdout.write('\r' + Colors.INFO + '[+]' + Colors.END + ' Progress: ' + Colors.INFO + '|' + bar + (21-len(bar))*' ' + '|'  + Colors.END + ' ' + str(percentage) + '%')
    else:
        sys.stdout.write('\r' + '[+]' + ' Progress: ' + '|' + bar + (21-len(bar))*' ' + '|' + ' ' + str(percentage) + '%')
    if(percentage==100):
        sys.stdout.write('\n')
    sys.stdout.flush()
