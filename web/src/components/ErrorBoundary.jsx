import React from "react";

// A render error in one tab shows a message there and leaves the page, the tab bar and the other tab alone.
export default class ErrorBoundary extends React.Component {
  constructor(props) { super(props); this.state = { failed: false }; }
  static getDerivedStateFromError() { return { failed: true }; }
  componentDidCatch() { /* nothing to log: the message is shown below and no text is echoed */ }
  componentDidUpdate(prev) { if (this.state.failed && prev.resetKey !== this.props.resetKey) this.setState({ failed: false }); }
  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <section className="card" role="alert" data-testid="boundary">
        <h2>This tab could not be shown</h2>
        <p>Something in this tab failed to display. The rest of the page still works. <button type="button" className="btn" onClick={() => this.setState({ failed: false })}>Try again</button></p>
      </section>
    );
  }
}
