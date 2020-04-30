
import plotly.graph_objects as go

fig = go.Figure(data=[go.Table(header=dict(values=['Candidate Password List', 'Number of Passwords Broken', 'List Size', 'Time (s)']),
                               cells=dict(values=[["Common Passwords", "Common Passwords + Special Chars",  "Common Passwords + Special Chars + Forward/Reversed", "English Words", "English Words + Special Chars", "English Words + Special Chars + Forward/Reversed", "Everything"],
                                [2348, 8494, 8532, 469, 3710, 3749, 9268], [10000, 1817124, 3634248, 40000, 7791636, 15583272, 19217520], [.038, 7.14, 14.8, .168, 31.77, 63.21, 75.20]]))
                      ])
fig.show()
